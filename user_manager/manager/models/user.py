from typing import Any, List

from pydantic import BaseModel

from user_manager.common.config import UserProperty


class UserPropertyWithKey(UserProperty):
    key: str


class UserPropertyWithValue(UserPropertyWithKey):
    value: Any


class UserViewData(BaseModel):
    user_id: str
    properties: List[UserPropertyWithValue]


class UserListProperty(BaseModel):
    key: str
    value: Any


class UserListViewData(BaseModel):
    user_id: str
    properties: List[UserListProperty]


class UsersListViewData(BaseModel):
    properties: List[UserPropertyWithKey]
    users: List[UserListViewData]


class PasswordInWrite(BaseModel):
    new_password: str
