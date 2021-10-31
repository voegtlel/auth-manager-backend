from datetime import datetime
from enum import Enum
from typing import List, Optional, Any, Dict

from pydantic import Field, PrivateAttr
from pytz import UTC, timezone, UnknownTimeZoneError

from user_manager.common.models.base import BaseDocument, BaseSubDocument


class DbEnumValue(BaseSubDocument):
    value: str
    title: str


class UserPropertyType(str, Enum):
    str = 'str'
    multistr = 'multistr'
    int = 'int'
    datetime = 'datetime'
    date = 'date'
    bool = 'bool'
    enum = 'enum'
    password = 'password'
    email = 'email'
    picture = 'picture'
    groups = 'groups'
    token = 'token'
    access_token = 'access_token'


class AccessType(str, Enum):
    everybody = 'everybody'
    self = 'self'
    only_self = 'only_self'
    admin = 'admin'
    nobody = 'nobody'

    def has_access(self, is_self: bool = False, is_admin: bool = False) -> bool:
        return (
            self == AccessType.everybody or
            (self == AccessType.self and (is_self or is_admin)) or
            (self == AccessType.only_self and is_self) or
            (self == AccessType.admin and is_admin)
        )


class DbUserProperty(BaseSubDocument):
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
    values: Optional[List[DbEnumValue]]
    template: Optional[str]
    required: Optional[bool]

    protected: bool = False


class DbUserScopeProperty(BaseSubDocument):
    user_property: str
    key: Optional[str]

    group_type: Optional[str]
    group_by_name: Optional[bool]

    @property
    def valid_key(self) -> str:
        return self.key or self.user_property


class DbUserScope(BaseSubDocument):
    key: str
    title: str
    protected: bool = False
    properties: List[DbUserScopeProperty]


class DbGroupType(BaseSubDocument):
    key: str
    title: str


class DbManagerSchema(BaseDocument):
    __indexes__ = []
    __collection_name__ = 'manager_schema'

    id: int = Field(0, alias='_id')

    user_properties: List[DbUserProperty] = []
    scopes: List[DbUserScope]
    group_types: List[DbGroupType]

    _properties_by_key: Optional[Dict[str, DbUserProperty]] = PrivateAttr(None)
    _scopes_by_key: Optional[Dict[str, DbUserScope]] = PrivateAttr(None)
    _group_types_by_key: Optional[Dict[str, DbGroupType]] = PrivateAttr(None)

    @property
    def scopes_by_key(self) -> Dict[str, DbUserScope]:
        if self._scopes_by_key is None:
            self._scopes_by_key = {
                scope.key: scope
                for scope in self.scopes
            }
        return self._scopes_by_key

    @property
    def properties_by_key(self) -> Dict[str, DbUserProperty]:
        if self._properties_by_key is None:
            self._properties_by_key = {
                user_property.key: user_property
                for user_property in self.user_properties
            }
        return self._properties_by_key

    @property
    def group_types_by_key(self) -> Dict[str, DbGroupType]:
        if self._group_types_by_key is None:
            self._group_types_by_key = {
                group_type.key: group_type
                for group_type in self.group_types
            }
        return self._group_types_by_key

    def get_tz(self, zoneinfo: str = None) -> datetime.tzinfo:
        if zoneinfo is None:
            zoneinfo = self.properties_by_key['zoneinfo'].default
        try:
            return timezone(zoneinfo)
        except UnknownTimeZoneError:
            return UTC
