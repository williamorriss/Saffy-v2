# CAS spec:
# https://unicon.github.io/cas/development/protocol/CAS-Protocol-V2-Specification.html

import base64
import xml.etree.ElementTree as ET
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast

import httpx
import jwt
from aiosqlite import Connection, OperationalError
from fastapi import APIRouter, Depends, HTTPException
from fastapi.requests import Request
from fastapi.responses import RedirectResponse, Response
from httpx import URL as HttpxURL
from httpx import AsyncClient as HttpxAsyncClient
from pydantic import Base64UrlStr, BaseModel, HttpUrl

import src.config as cfg
from src.config import DependsConfig
from src.database import DependsDB
from src.log import DependsLogger

router = APIRouter(prefix="/auth")


class UserSchema(BaseModel):
    username: str
    date_joined: datetime
    profile_picture: str | None


def authorize(request: Request) -> int:
    """Extracts `user_id` from jwt bearer token"""
    config = cfg.get_config(request)
    auth_token = request.cookies.get("auth-token")
    if auth_token is None:
        raise HTTPException(status_code=401, detail="No auth token")

    try:
        claims = jwt.decode(
            jwt=auth_token,
            key=config.jwt_key,
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Expired token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid auth token")

    return cast(int, claims["user_id"])


def get_hostname(request: Request) -> HttpUrl:
    """Gets server hostname from request body"""
    return HttpUrl(str(request.base_url))


DependsUserId = Annotated[int, Depends(authorize)]
DependsHostname = Annotated[HttpUrl, Depends(get_hostname)]

# url helpers

def _validate_redirect(url: str, allowed_origins: Collection[str]) -> HttpxURL:
    try:
        parsed = HttpxURL(url)
    except httpx.InvalidURL:
        raise HTTPException(status_code=400, detail="Redirect is not a valid URL")

    # if strip_origin(parsed) not in allowed_origins:
    #     raise HTTPException(status_code=400, detail="Bad origin")

    return parsed


def _cas_service_url(origin: HttpUrl, redirect64: Base64UrlStr) -> HttpUrl:
    return HttpUrl(f"{str(origin).rstrip('/')}/api/auth/cas/{redirect64}")


def _cas_logout_response(cas_origin: HttpUrl) -> RedirectResponse:
    response = RedirectResponse(url=f"{cas_origin}/logout", status_code=302)
    response.delete_cookie("auth-token")
    return response


# endpoints


@router.get("/login", response_class=RedirectResponse)
async def login(
    hostname: DependsHostname,
    redirect: HttpUrl,
    config: DependsConfig,
    log: DependsLogger,
) -> RedirectResponse:
    """Logs in user via CAS"""
    redirect_url = _validate_redirect(str(redirect), config.allowed_origins)
    redirect64 = base64.urlsafe_b64encode(str(redirect_url).encode()).decode()
    callback = _cas_service_url(hostname, redirect64)
    cas_login = HttpxURL(f"{config.cas_origin}/login", params={"service": callback})

    log.info(f"host name: {hostname}")
    return RedirectResponse(url=str(cas_login), status_code=302)


@router.get("/logout", response_class=RedirectResponse)
async def logout(config: DependsConfig) -> RedirectResponse:
    """Logs user out"""
    return _cas_logout_response(config.cas_origin)


@router.get("/cas/{redirect64}", response_class=RedirectResponse)
async def cas_callback(
    hostname: DependsHostname,
    redirect64: str,
    ticket: str,
    config: DependsConfig,
    db: DependsDB,
) -> RedirectResponse:
    """Handles CAS redirect after auth"""
    redirect = _validate_redirect(
        base64.urlsafe_b64decode(redirect64).decode(), config.allowed_origins
    )

    username = await _get_username(redirect64, ticket, hostname, config.cas_origin)
    user_id = await _get_user_id(db, username)

    if not user_id:
        user_id = await _create_user(db, username)

    if not user_id:
        raise HTTPException(status_code=500, detail="Failed to create new user")

    expires = datetime.now(UTC) + timedelta(hours=1)
    token = jwt.encode(
        {"user_id": user_id, "exp": int(expires.timestamp())},
        key=config.jwt_key,
        algorithm="HS256",
    )

    response = RedirectResponse(url=str(redirect), status_code=302)
    response.set_cookie(
        key="auth-token", value=token, httponly=True, expires=expires
    )  # set true in prod

    return response


@router.get("/session", response_model=UserSchema)
async def retrieve_session(user_id: DependsUserId, db: DependsDB) -> UserSchema:
    """Retrieves user data for a signed in session"""
    async with db.execute(
        """
        SELECT Username, DateJoined, URL FROM Users 
        LEFT JOIN Images ON ImageID = Images.ID 
        WHERE Users.ID = ?""",
        (user_id,),
    ) as cursor:
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    username, date_joined, profile_picture = row
    return UserSchema(
        username=username, date_joined=date_joined, profile_picture=profile_picture
    )


@router.get("/refresh", response_class=Response)
async def refresh_token(config: DependsConfig, user_id: DependsUserId) -> Response:
    """Refreshes JWT token for a signed-in session without another login"""
    expires = datetime.now(UTC) + timedelta(hours=1)
    token = jwt.encode(
        {"user_id": user_id, "exp": int(expires.timestamp())},
        key=config.jwt_key,
        algorithm="HS256",
    )

    response = Response()
    response.set_cookie(key="auth-token", value=token, httponly=True, expires=expires)

    return response


@router.get("/delete", response_class=RedirectResponse)
async def delete_user(
    user_id: DependsUserId,
    db: DependsDB,
    config: DependsConfig,
) -> RedirectResponse:
    """Deletes user session and data from database"""
    try:
        async with db.execute("DELETE FROM users WHERE id = ?", (user_id,)) as cursor:
            await db.commit()
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")

        return _cas_logout_response(config.cas_origin)

    except OperationalError:
        raise HTTPException(status_code=500, detail="Server error")


async def _get_username(redirect64: str, ticket: str, origin: HttpUrl, cas_origin: HttpUrl) -> str:
    async with HttpxAsyncClient(base_url=str(cas_origin)) as cas_client:
        response = await cas_client.get(
            "/serviceValidate",
            params={"service": str(_cas_service_url(origin, redirect64)), "ticket": ticket},
        )

    namespaces = {"cas": "http://www.yale.edu/tp/cas"}
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError:
        raise HTTPException(status_code=502, detail="Bad CAS response")

    if failure := root.find("cas:authenticationFailure", namespaces):
        error = (
            failure.findtext("cas:message", namespaces=namespaces) or "No error found"
        )
        print(error)
        raise HTTPException(status_code=401, detail="Failed to authenticate")

    if (success := root.find("cas:authenticationSuccess", namespaces)) is None:
        raise HTTPException(status_code=500, detail="No CAS response")

    if not (user := success.findtext("cas:user", namespaces=namespaces)):
        raise HTTPException(
            status_code=500, detail="Server error whilst parsing CAS response"
        )

    return user


async def _get_user_id(db: Connection, username: str) -> int | None:
    async with db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ) as cursor:
        row = await cursor.fetchone()
        return row[0] if row else None


async def _create_user(db: Connection, username: str) -> int | None:
    async with db.execute(
        "INSERT INTO users (username) VALUES (?)", (username,)
    ) as cursor:
        await db.commit()
        return cursor.lastrowid
