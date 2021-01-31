from datetime import datetime
from typing import List, Any

from pydantic import BaseModel


class UserHistoryChange(BaseModel):
    property: str
    value: Any


class UserHistoryInList(BaseModel):
    timestamp: datetime

    author_id: str

    changes: List[UserHistoryChange]
