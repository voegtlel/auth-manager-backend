from typing import Any, List, Optional

from pydantic import BaseModel

from user_manager.common.models import UserGroupPropertyType
from user_manager.manager.models.schema import UserProperty


class UserPropertyWithValue(UserProperty):
    value: Any


class UserViewDataGroup(BaseModel):
    title: str
    type: UserGroupPropertyType
    properties: List[UserPropertyWithValue]


class UserViewData(BaseModel):
    user_id: str
    view_groups: List[UserViewDataGroup]


class UserListProperty(BaseModel):
    key: str
    value: Any


class UserListViewData(BaseModel):
    user_id: str
    properties: List[UserListProperty]


class UsersListViewData(BaseModel):
    view_id: str
    view_name: str
    properties: List[UserProperty]
    users: List[UserListViewData]


class PasswordReset(BaseModel):
    email: str


class PasswordInWrite(BaseModel):
    password: str


class PasswordResetResult(BaseModel):
    reset_link: Optional[str] = None
