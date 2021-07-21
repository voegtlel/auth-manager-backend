import re
from typing import List, Optional

from authlib.oauth2.rfc6749 import (
    ClientMixin)
from authlib.oauth2.rfc6749.util import list_to_scope, scope_to_list
from pydantic import Field
from pymongo import IndexModel, ASCENDING

from user_manager.common.models.base import BaseSubDocument, BaseDocument


class DbAccessGroup(BaseSubDocument):
    group: str
    roles: List[str]


class DbClient(BaseDocument, ClientMixin):
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

    access_groups: List[DbAccessGroup]


class DbClientUserCache(BaseDocument):
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
