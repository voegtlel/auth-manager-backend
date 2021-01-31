from typing import List, Optional

from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseDocument


class DbUserGroup(BaseDocument):
    __indexes__ = [
        IndexModel([('member_groups', ASCENDING)]),
        IndexModel([('members', ASCENDING)]),
    ]
    __collection_name__ = 'user_group'

    id: str = Field(..., alias='_id')

    group_name: str
    group_type: str
    notes: Optional[str] = Field(None, max_length=1024 * 1024)

    visible: bool

    member_groups: List[str] = []
    members: List[str] = []

    enable_email: bool = False
    enable_postbox: bool = False
    postbox_quota: int = 0
    email_forward_members: List[str] = []
    email_allowed_forward_members: List[str] = []
    email_postbox_access_members: List[str] = []
