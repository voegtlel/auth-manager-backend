from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseDocument


class DbGroupMail(BaseDocument):
    __indexes__ = [
        IndexModel([('group_id', ASCENDING)], sparse=True),
    ]
    __collection_name__ = 'group_mail'

    id: str = Field(..., alias='_id')
    group_id: str
    from_address: str

    mail_path: str
