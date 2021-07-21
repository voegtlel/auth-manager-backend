from typing import List, Optional, Any

from pydantic import BaseModel

from user_manager.common.models import UserPropertyType, AccessType


class EnumValue(BaseModel):
    value: str
    title: str


class UserProperty(BaseModel):
    key: str

    type: UserPropertyType = ...
    format: Optional[str]
    format_help: Optional[str]
    can_edit: AccessType = AccessType.nobody
    can_read: AccessType = AccessType.everybody
    write_once: bool = False
    default: Optional[Any]
    visible: AccessType = AccessType.everybody
    title: str
    values: Optional[List[EnumValue]]
    template: Optional[str]
    required: Optional[bool]

    protected: bool = False


class UserScopeProperty(BaseModel):
    user_property: str
    key: Optional[str]

    group_type: Optional[str]


class UserScope(BaseModel):
    key: str
    title: str
    protected: bool
    properties: List[UserScopeProperty]


class GroupType(BaseModel):
    key: str
    title: str


class ManagerSchema(BaseModel):
    user_properties: List[UserProperty] = []
    scopes: List[UserScope]
    group_types: List[GroupType]
