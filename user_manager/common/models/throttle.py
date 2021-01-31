from datetime import datetime

from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseDocument


class DbIpLoginThrottle(BaseDocument):
    __indexes__ = [
        IndexModel([('forget_time', ASCENDING)], expireAfterSeconds=0),
    ]
    __collection_name__ = 'ipLoginThrottle'

    ip: str = Field(..., alias='_id')

    retries: int = 1
    last_retry: datetime = ...
    next_retry: datetime = ...
    forget_time: datetime = ...
