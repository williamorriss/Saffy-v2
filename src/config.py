from typing import Annotated, cast

from fastapi import Depends
from fastapi.requests import Request
from pydantic import BaseModel, ConfigDict, HttpUrl


class Config(BaseModel):
    """Immutable structure to hold the current configuration of the server"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    jwt_key: str
    imgbb_key: str
    allowed_origins: tuple[str, ...] = ()
    cas_origin: HttpUrl = HttpUrl("https://auth.bath.ac.uk")


# extractors
def get_config(request: Request) -> Config:
    """
    Extractor to get the current configuration of the server

    ```python
        config: AppConfig = Depends(get_config)
    ```
    """
    return cast(Config, request.app.state.config)


# api route type
DependsConfig = Annotated[Config, Depends(get_config)]
