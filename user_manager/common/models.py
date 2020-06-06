import re
from datetime import datetime
from typing import List, Optional

import pytz
from authlib.oauth2.rfc6749 import (
    TokenMixin,
    ClientMixin)
from authlib.oauth2.rfc6749.util import list_to_scope, scope_to_list
from authlib.oidc.core import AuthorizationCodeMixin
from pydantic import BaseModel, Field, Extra
from pymongo import IndexModel, HASHED, ASCENDING


class BaseSubDocument(BaseModel):
    class Config:
        allow_population_by_field_name = True
        validate_assignment = True


class BaseDocument(BaseSubDocument):
    __indexes__: List[IndexModel] = []
    __collection_name__: str

    def update_from(self, src_doc):
        if isinstance(src_doc, BaseModel):
            for key in src_doc.__fields__.keys():
                if key in self.__fields__:
                    setattr(self, key, getattr(src_doc, key))


class AuthorizationCode(BaseDocument, AuthorizationCodeMixin):
    __indexes__ = [
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
        IndexModel([('user_id', ASCENDING)]),
    ]
    __collection_name__ = 'authorization_code'

    code: str = Field(..., alias='_id')

    user_id: str = ...
    client_id: str
    redirect_uri: str
    response_type: Optional[str]
    scope: Optional[str]
    nonce: Optional[str]
    auth_time: int = ...
    expiration_time: datetime = ...

    code_challenge: Optional[str]
    code_challenge_method: Optional[str]

    def is_expired(self):
        return self.expiration_time < datetime.utcnow()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class Token(BaseDocument, TokenMixin, AuthorizationCodeMixin):
    __indexes__ = [
        IndexModel([('refresh_token', HASHED)]),
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
        IndexModel([('user_id', ASCENDING)]),
    ]
    __collection_name__ = 'token'

    access_token: str = Field(..., alias='_id')

    user_id: str
    client_id: str
    token_type: str
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    revoked: bool = False
    auth_time: int = ...
    issued_at: int = ...
    expires_in: int = 0
    expiration_time: datetime = ...

    def is_expired(self):
        return self.expiration_time < datetime.utcnow()

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return int(self.expiration_time.replace(tzinfo=pytz.UTC).timestamp())

    def get_redirect_uri(self):
        return None

    def get_nonce(self):
        return None

    def get_auth_time(self):
        return self.auth_time


class Session(BaseDocument):
    __indexes__ = [
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
        IndexModel([('user_id', ASCENDING)]),
    ]
    __collection_name__ = 'session'

    id: str = Field(..., alias='_id')

    user_id: str = ...
    issued_at: int = ...
    expires_in: int = 0
    expiration_time: datetime = ...


class IpLoginThrottle(BaseDocument):
    __indexes__ = [
        IndexModel([('forget_time', ASCENDING)], expireAfterSeconds=0),
    ]
    __collection_name__ = 'ipLoginThrottle'

    ip: str = Field(..., alias='_id')

    retries: int = 1
    last_retry: datetime = ...
    next_retry: datetime = ...
    forget_time: datetime = ...


class AccessGroup(BaseSubDocument):
    group: str
    roles: List[str]


class Client(BaseDocument, ClientMixin):
    __indexes__ = [
        IndexModel([('access_groups.group', ASCENDING)]),
    ]
    __collection_name__ = 'client'

    id: str = Field(..., alias='_id')

    notes: Optional[str] = Field(None, max_length=1024*1024)

    redirect_uri: List[str]
    allowed_scope: List[str]
    client_secret: Optional[str] = None
    token_endpoint_auth_method: List[str] = ['client_secret_basic']
    response_type: List[str] = []
    grant_type: List[str] = []

    def get_client_id(self):
        return self.id

    def get_default_redirect_uri(self):
        return self.redirect_uri[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(scope_to_list(self.allowed_scope))
        return list_to_scope([s for s in scope.split() if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return any(re.fullmatch(chk_redirect_uri, redirect_uri) for chk_redirect_uri in self.redirect_uri)

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_token_endpoint_auth_method(self, method):
        return any(
            method == chk_token_endpoint_auth_method
            for chk_token_endpoint_auth_method in self.token_endpoint_auth_method
        )

    def check_response_type(self, response_type):
        return any(
            response_type == chk_response_type
            for chk_response_type in self.response_type
        )

    def check_grant_type(self, grant_type):
        return any(
            grant_type == chk_grant_type
            for chk_grant_type in self.grant_type
        )

    access_groups: List[AccessGroup]


class ClientUserCache(BaseDocument):
    __indexes__ = [
        IndexModel([('client_id', ASCENDING), ('user_id', ASCENDING)]),
        IndexModel([('user_id', ASCENDING)]),
        IndexModel([('groups', ASCENDING)]),
    ]
    __collection_name__ = 'client_user_cache'

    id: str = Field(..., alias='_id')

    client_id: str
    user_id: str

    groups: List[str]
    roles: List[str]

    last_modified: int


class UserGroup(BaseDocument):
    __indexes__ = [
        IndexModel([('member_groups', ASCENDING)]),
        IndexModel([('members', ASCENDING)]),
    ]
    __collection_name__ = 'user_group'

    id: str = Field(..., alias='_id')

    group_name: str
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


class User(BaseDocument):

    class Config:
        extra = Extra.allow

    __indexes__ = [
        IndexModel([('email', ASCENDING)], unique=True),
        IndexModel([('preferred_username', ASCENDING)], unique=True),
        IndexModel([('registration_token', HASHED)]),
        IndexModel([('email_verification_token', HASHED)]),
        IndexModel([('password_reset_token', HASHED)]),
        IndexModel([('groups', ASCENDING)]),
        IndexModel([('email_postbox_access_token', ASCENDING)]),
        IndexModel([('email_alias', ASCENDING)]),
    ]
    __collection_name__ = 'user'

    id: str = Field(..., alias='_id')
    notes: Optional[str] = Field(None, max_length=1024 * 1024)

    password: Optional[str] = None
    password_reset_token: Optional[str] = None

    active: bool = False

    registration_token: Optional[str] = None

    email: str
    email_verified: bool = False
    email_verification_token: Optional[str] = None

    phone_number: Optional[str] = None
    phone_number_verified: bool = False

    preferred_username: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]

    picture: Optional[str]

    locale: Optional[str]
    zoneinfo: Optional[str]
    updated_at: Optional[int]

    groups: List[str] = []
    email_allowed_forward_groups: List[str] = []
    email_forward_groups: List[str] = []
    email_postbox_access_groups: List[str] = []
    email_postbox_access_token: Optional[str]
    has_email_alias: Optional[bool]
    forward_emails: Optional[bool]
    email_alias: Optional[str]
