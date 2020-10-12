from typing import Optional

from pydantic import BaseModel


class ErrorResult(BaseModel):
    error: str
    error_description: Optional[str]
    error_uri: Optional[str]
    state: Optional[str]
