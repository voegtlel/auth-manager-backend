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
    group_type: str
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

    email_managed_mailing_list: bool = False
    email_managed_mailing_list_notify_members: List[str] = []
    email_managed_mailing_list_forward_to_notifiers: bool = False
    email_managed_mailing_list_send_notification_to_sender: bool = False


class GroupInRead(GroupBase):
    id: str


class GroupInWrite(GroupBase):
    pass


class GroupInCreate(GroupBase):
    id: str
