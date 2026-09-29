from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from src.auth import router as auth_router
from src.config import Config
from src.database import init_db


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, Any]:
    """Context manager for lifespan of application.
    Handles initiation of database on startup."""
    await init_db()
    yield


config = Config(
    jwt_key="aeui4baibviruabirbviruiadbiburbaiurbaiuriabir213io3u4iu23o4u23oiu4",
    imgbb_key="f7616c52863e992deb9e183c38a22468",
    allowed_origins=("http://localhost:5173", "http://127.0.0.1:8000"),
)

# noinspection PyTypeChecker
app = FastAPI(
    lifespan=lifespan,
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=[str(o).rstrip("/") for o in config.allowed_origins],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Accept"],
        )
    ],
)


app.include_router(auth_router, prefix="/api")

app.state.config = config
