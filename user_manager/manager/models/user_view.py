from datetime import datetime, date
from typing import List, Optional, Union

from pydantic import BaseModel

from user_manager.common.models import UserFilterOp
from user_manager.common.models.user_view import UserGroupPropertyType


class UserFilter(BaseModel):
    op: UserFilterOp
    field: Optional[str]
    value: Optional[Union[bool, datetime, date, str, int, float]]
    operands: Optional[List['UserFilter']]
    operand: Optional['UserFilter']


UserFilter.update_forward_refs()


class UserViewGroup(BaseModel):
    title: str
    type: UserGroupPropertyType
    user_properties: List[str] = []


class UserViewInList(BaseModel):
    id: str

    group_id: Optional[str]
    name: str

    filter: Optional[UserFilter]

    protected: Optional[bool]


class UserViewBase(BaseModel):
    name: str

    filter: Optional[UserFilter]

    # List view properties (without groups)
    list_properties: List[str] = []
    # Detail properties
    view_groups: List[UserViewGroup]


class UserViewInRead(UserViewBase):
    id: str

    group_id: Optional[str]

    protected: Optional[bool]


class UserViewInWrite(UserViewBase):
    pass
