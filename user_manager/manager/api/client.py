from typing import List

from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from fastapi.params import Body

from user_manager.common.models import Client
from user_manager.common.mongo import client_user_cache_collection, client_collection
from user_manager.manager.auth import Authentication
from user_manager.manager.models import ClientInRead, ClientInList, ClientInWrite, ClientInCreate

router = APIRouter()


@router.get(
    '/clients',
    tags=['User Manager'],
    response_model=List[ClientInList],
)
def get_clients(
        user: UserInfo = Depends(Authentication()),
) -> List[ClientInList]:
    """Gets all clients."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    return [
        ClientInList.validate(Client.validate(client)) for client in client_collection.find()
    ]


@router.post(
    '/clients',
    tags=['User Manager'],
    status_code=201
)
def create_client(
        client_data: ClientInCreate = Body(...),
        user: UserInfo = Depends(Authentication()),
):
    """Creates a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    new_client = Client.validate(client_data)
    client_collection.insert_one(new_client.dict(exclude_none=True, by_alias=True))


@router.get(
    '/clients/{client_id}',
    tags=['User Manager'],
)
def get_client(
        client_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Gets a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    client_data = client_collection.find_one({'_id': client_id})
    if client_data is None:
        raise HTTPException(404)
    return ClientInRead.validate(Client.validate(client_data))


@router.put(
    '/clients/{client_id}',
    tags=['User Manager'],
)
def update_client(
        client_id: str,
        client_update: ClientInWrite,
        user: UserInfo = Depends(Authentication()),
):
    """Updates a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    if client_collection.count_documents({'_id': client_id}) != 1:
        raise HTTPException(404)

    client = Client.validate(client_update)
    client_user_cache_collection.delete_many({'client_id': client_id})
    result = client_collection.replace_one({'_id': client_id}, client.dict(exclude_none=True, by_alias=True))
    if result.matched_count != 1:
        raise HTTPException(404)


@router.delete(
    '/clients/{client_id}',
    tags=['User Manager'],
)
def delete_client(
        client_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Deletes a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    client_user_cache_collection.delete_many({'client_id': client_id})
    result = client_collection.delete_one({'_id': client_id})
    if result.deleted_count != 1:
        raise HTTPException(404)
