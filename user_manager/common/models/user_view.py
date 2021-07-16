from datetime import datetime, date
from enum import Enum
from typing import List, Optional, Union

from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseDocument, BaseSubDocument


class UserFilterOp(str, Enum):
    And = 'and'
    Or = 'or'
    Eq = 'eq'
    Ne = 'ne'
    Gt = 'gt'
    Lt = 'lt'
    Ge = 'ge'
    Le = 'le'
    Not = 'not'


class DbUserFilter(BaseSubDocument):
    op: UserFilterOp
    field: Optional[str]
    value: Optional[Union[bool, datetime, date, str, int, float]]
    operands: Optional[List['DbUserFilter']]
    operand: Optional['DbUserFilter']

    def _get_key(self) -> str:
        if self.op == UserFilterOp.And:
            return '$and'
        elif self.op == UserFilterOp.Or:
            return '$or'
        elif self.op == UserFilterOp.Not:
            return '$nor'
        elif self.op in (
                UserFilterOp.Eq, UserFilterOp.Ne, UserFilterOp.Gt, UserFilterOp.Lt, UserFilterOp.Ge, UserFilterOp.Le
        ):
            return self.field
        raise ValueError(f"Invalid op: {self.op}")

    def to_mongodb(self) -> dict:
        if self.op == UserFilterOp.And:
            operands_keys = [op._get_key() for op in self.operands]
            if len(set(operands_keys)) == len(operands_keys):
                return {
                    k: v
                    for operand in self.operands
                    for k, v in operand.items()
                }
            else:
                return {
                    '$and': [
                        operand.to_mongodb()
                        for operand in self.operands
                    ]
                }
        elif self.op == UserFilterOp.Or:
            return {
                '$or': [
                    {operand._get_key(): operand.to_mongodb()}
                    for operand in self.operands
                ]
            }
        elif self.op == UserFilterOp.Not:
            return {
                '$nor': [self.operand.to_mongodb()]
            }
        elif self.op in (
                UserFilterOp.Eq, UserFilterOp.Ne, UserFilterOp.Gt, UserFilterOp.Lt, UserFilterOp.Ge, UserFilterOp.Le
        ):
            return {self.field: self.value}
        raise ValueError(f"Invalid op: {self.op}")


DbUserFilter.update_forward_refs()


class UserGroupPropertyType(str, Enum):
    default = 'default'
    email = 'email'
    password = 'password'
    groups = 'groups'


class DbUserViewGroup(BaseSubDocument):
    type: UserGroupPropertyType = UserGroupPropertyType.default
    title: str
    user_properties: List[str] = []


class DbUserView(BaseDocument):
    __indexes__ = [
        IndexModel([('group_id', ASCENDING)], sparse=True),
    ]
    __collection_name__ = 'user_view'

    id: str = Field(..., alias='_id')
    group_id: Optional[str]
    name: str

    filter: Optional[DbUserFilter]

    # List view properties (without groups)
    list_properties: List[str] = []
    # Detail properties
    view_groups: List[DbUserViewGroup]

    protected: Optional[bool]
