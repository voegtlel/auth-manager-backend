from typing import List
from uuid import uuid4

from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from fastapi.params import Body

from user_manager.common.models import DbClient
from user_manager.common.mongo import async_client_collection, async_client_user_cache_collection
from user_manager.manager.auth import Authentication
from user_manager.manager.models import ClientInRead, ClientInList, ClientInWrite, ClientInCreate

router = APIRouter()


@router.get(
    '/clients',
    tags=['User Manager'],
    response_model=List[ClientInList],
)
async def get_clients(
        user: UserInfo = Depends(Authentication()),
) -> List[ClientInList]:
    """Gets all clients."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    return [
        ClientInList.validate(DbClient.validate_document(client)) async for client in async_client_collection.find()
    ]


@router.post(
    '/clients',
    tags=['User Manager'],
    status_code=201
)
async def create_client(
        client_data: ClientInCreate = Body(...),
        user: UserInfo = Depends(Authentication()),
):
    """Creates a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    new_client = DbClient.validate_override(client_data)
    await async_client_collection.insert_one(new_client.document())


@router.get(
    '/clients/{client_id}',
    tags=['User Manager'],
)
async def get_client(
        client_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Gets a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    client_data = await async_client_collection.find_one({'_id': client_id})
    if client_data is None:
        raise HTTPException(404)
    return ClientInRead.validate(DbClient.validate_document(client_data))


@router.put(
    '/clients/{client_id}',
    tags=['User Manager'],
)
async def update_client(
        client_id: str,
        client_update: ClientInWrite,
        user: UserInfo = Depends(Authentication()),
):
    """Updates a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    if await async_client_collection.count_documents({'_id': client_id}) != 1:
        raise HTTPException(404)

    client = DbClient.validate_document(client_update)
    await async_client_user_cache_collection.delete_many({'client_id': client_id})
    result = await async_client_collection.replace_one(
        {'_id': client_id},
        client.document(),
    )
    if result.matched_count != 1:
        raise HTTPException(404)


@router.delete(
    '/clients/{client_id}',
    tags=['User Manager'],
)
async def delete_client(
        client_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Deletes a client."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    await async_client_user_cache_collection.delete_many({'client_id': client_id})
    result = await async_client_collection.delete_one({'_id': client_id})
    if result.deleted_count != 1:
        raise HTTPException(404)
