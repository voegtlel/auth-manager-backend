from datetime import datetime
from typing import List, Any

from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseSubDocument, BaseDocument


class DbChange(BaseSubDocument):
    property: str
    value: Any


class DbUserHistory(BaseDocument):
    __indexes__ = [
        IndexModel([('user_id', ASCENDING), ('timestamp', ASCENDING)]),
    ]
    __collection_name__ = 'user_history'

    id: str = Field(..., alias='_id')
    user_id: str
    timestamp: datetime

    author_id: str

    changes: List[DbChange]
