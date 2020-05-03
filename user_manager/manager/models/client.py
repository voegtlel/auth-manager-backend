from typing import List, Optional

from pydantic import BaseModel


class ClientInList(BaseModel):
    id: str


class ClientAccessGroup(BaseModel):
    group: str
    roles: List[str]


class ClientInRead(BaseModel):
    id: str

    notes: Optional[str]

    redirect_uri: List[str]
    allowed_scope: List[str]
    client_secret: Optional[str] = None
    token_endpoint_auth_method: List[str] = ['client_secret_basic']
    response_type: List[str] = []
    grant_type: List[str] = []

    access_groups: List[ClientAccessGroup]


class ClientInWrite(BaseModel):
    id: str

    notes: Optional[str]

    redirect_uri: List[str]
    allowed_scope: List[str]
    client_secret: Optional[str] = None
    token_endpoint_auth_method: List[str] = ['client_secret_basic']
    response_type: List[str] = []
    grant_type: List[str] = []

    access_groups: List[ClientAccessGroup]


class ClientInCreate(ClientInWrite):
    pass
