from datetime import datetime
from typing import Dict, Any

from pydantic import Field
from pymongo import IndexModel, ASCENDING, DESCENDING

from user_manager.common.models.base import BaseDocument


class DbGroupMail(BaseDocument):
    __indexes__ = [
        IndexModel([('group_id', ASCENDING), ('approved', ASCENDING), ('timestamp', DESCENDING)]),
        IndexModel([('approved', ASCENDING)]),
    ]
    __collection_name__ = 'group_mail'

    id: str = Field(..., alias='_id')
    timestamp: datetime
    group_id: str

    metadata: Dict[str, Any]

    path: str

    approved: bool
