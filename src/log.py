import logging
from logging import LoggerAdapter
from typing import Annotated

from fastapi import Depends, Request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

logger = logging.getLogger(__name__)


def get_logger(request: Request) -> LoggerAdapter:
    """Gets current logger and appends request context"""
    return LoggerAdapter(
        logger,
        extra={
            "path": request.url.path,
            "method": request.method,
            "request_id": request.headers.get("x-request-id"),
        },
    )


DependsLogger = Annotated[LoggerAdapter, Depends(get_logger)]
