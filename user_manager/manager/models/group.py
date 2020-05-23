from typing import List, Optional

from pydantic import BaseModel


class GroupInList(BaseModel):
    id: str

    group_name: str
    visible: bool

    enable_email: bool
    enable_postbox: bool


class GroupBase(BaseModel):
    group_name: str
    notes: Optional[str]

    visible: bool

    member_groups: List[str] = []
    members: List[str] = []

    enable_email: bool = False
    enable_postbox: bool = False
    postbox_quota: int = 0
    email_forward_members: List[str] = []
    email_allowed_forward_members: List[str] = []
    email_postbox_access_members: List[str] = []


class GroupInRead(GroupBase):
    id: str


class GroupInWrite(GroupBase):
    pass


class GroupInCreate(GroupBase):
    id: str
