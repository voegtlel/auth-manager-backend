from datetime import datetime

from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseDocument


class DbSession(BaseDocument):
    __indexes__ = [
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
        IndexModel([('user_id', ASCENDING)]),
    ]
    __collection_name__ = 'session'

    id: str = Field(..., alias='_id')

    user_id: str = ...
    issued_at: int = ...
    expires_in: int = 0
    expiration_time: datetime = ...
