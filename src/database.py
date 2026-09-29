from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from aiosqlite import Connection, Row, connect
from fastapi import Depends

DBNAME = "test.db"

SCHEMA: Path = Path(__file__).parents[1] / "sql" / "schema.sql"


@asynccontextmanager
async def get_db_contextmanager() -> AsyncGenerator[Connection, None]:
    """
    Gets db connection. Use `get_db` with Depends for routes etc where
    `Depends` can be used

    Note:
        This is an async context manager so use
        ```python
            async with get_db_contextmanager() as db:
             ...
        ```
        to use the connection
    """
    async with connect(DBNAME) as db:
        db.row_factory = Row
        yield db


async def get_db() -> AsyncGenerator[Connection, None]:
    """
    Gets db connection via dependency injection

    Note:
        Use this with db: ... = Depends(get_db)
        Otherwise `get_db_contextmanager`
    """
    async with connect(DBNAME) as db:
        db.row_factory = Row
        yield db


async def init_db() -> None:
    """
    Method to initialise database (local .db file)
    """
    async with connect(DBNAME) as db:
        await db.execute(
            "PRAGMA journal_mode=WAL"
        )  # Write Ahead Log for concurrent read/ writes
        await db.execute("PRAGMA busy_timeout=1000")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript(SCHEMA.read_text())
        await db.commit()
        print("Schema applied")


DependsDB = Annotated[Connection, Depends(get_db)]
