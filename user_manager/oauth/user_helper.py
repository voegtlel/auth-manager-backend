from typing import List, Dict, Optional, AsyncIterator

from authlib.common.security import generate_token
from fastapi import HTTPException
from pydantic.main import BaseModel

from user_manager.common.models import UserGroup, User, ClientUserCache, Client
from user_manager.common.mongo import user_group_collection, async_user_group_collection, client_collection, \
    client_user_cache_collection, async_client_collection, async_client_user_cache_collection, user_collection, \
    async_user_collection


def _resolve_groups(
        group_ids: List[str]
) -> Dict[str, List[str]]:
    return {
        group_data['_id']: [grp['_id'] for grp in group_data['sub_groups']]
        for group_data in user_group_collection.aggregate([
            {
                '$match': {'_id': {'$in': group_ids}},
            },
            {
                '$graphLookup': {
                    'from': UserGroup.__collection_name__,
                    'startWith': '$member_groups',
                    'connectFromField': 'member_groups',
                    'connectToField': '_id',
                    'as': 'sub_groups'
                }
            },
            {
                '$project': {
                    '_id': 1,
                    'sub_groups._id': 1,
                }
            }
        ])
    }


async def _async_resolve_groups(
        group_ids: List[str]
) -> Dict[str, List[str]]:
    return {
        group_data['_id']: [grp['_id'] for grp in group_data['sub_groups']]
        async for group_data in async_user_group_collection.aggregate([
            {
                '$match': {'_id': {'$in': group_ids}},
            },
            {
                '$graphLookup': {
                    'from': UserGroup.__collection_name__,
                    'startWith': '$member_groups',
                    'connectFromField': 'member_groups',
                    'connectToField': '_id',
                    'as': 'sub_groups'
                }
            },
            {
                '$project': {
                    '_id': 1,
                    'sub_groups._id': 1,
                }
            }
        ])
    }


def _create_user_cache_for_user_client(user_data: User, client_id: str) -> Optional[dict]:
    """Returns the cache entry or none if not authenticated."""
    user_groups = _resolve_groups(user_data.groups)

    all_user_groups = list({
        grp for grps in user_groups.values() for grp in grps
    } | set(user_groups.keys()))

    client = client_collection.find_one({'_id': client_id}, {'_id': 0, 'access_groups': 1})
    if client is None:
        return None

    common_groups = [
        access_group for access_group in client['access_groups'] if access_group['group'] in all_user_groups
    ]
    client_user_groups = [access_group['group'] for access_group in common_groups]
    client_user_roles = list(set(role for access_group in common_groups for role in access_group['roles']))
    effective_groups = set(client_user_groups) | {
        group for user_group in client_user_groups for group in user_groups.get(user_group, [])
    }
    if client_user_groups and client_user_roles:
        cache_entry = ClientUserCache(
            id=generate_token(30),
            client_id=client_id,
            user_id=user_data.id,
            groups=list(effective_groups),
            roles=client_user_roles,
            last_modified=user_data.updated_at,
        ).dict(exclude_none=True, by_alias=True)
        client_user_cache_collection.insert_one(cache_entry)
        return cache_entry
    return None


async def _async_create_user_cache_for_user_client(user_data: User, client_id: str) -> Optional[dict]:
    """Returns the cache entry or none if not authenticated."""
    user_groups = await _async_resolve_groups(user_data.groups)

    all_user_groups = list({
        grp for grps in user_groups.values() for grp in grps
    } | set(user_groups.keys()))

    client = await async_client_collection.find_one({'_id': client_id}, {'_id': 0, 'access_groups': 1})
    if client is None:
        return None

    common_groups = [
        access_group for access_group in client['access_groups'] if access_group['group'] in all_user_groups
    ]
    client_user_groups = [access_group['group'] for access_group in common_groups]
    client_user_roles = list(set(role for access_group in common_groups for role in access_group['roles']))
    effective_groups = set(client_user_groups) | {
        group for user_group in client_user_groups for group in user_groups.get(user_group, [])
    }
    if client_user_groups and client_user_roles:
        cache_entry = ClientUserCache(
            id=generate_token(30),
            client_id=client_id,
            user_id=user_data.id,
            groups=list(effective_groups),
            roles=client_user_roles,
            last_modified=user_data.updated_at,
        ).dict(exclude_none=True, by_alias=True)
        await async_client_user_cache_collection.insert_one(cache_entry)
        return cache_entry
    return None


class UserWithRoles(BaseModel):
    user: User
    roles: List[str]
    last_modified: int

    @staticmethod
    def load(user_id: str, client_id: str) -> Optional['UserWithRoles']:
        user_data = user_collection.find_one({'_id': user_id})
        if user_data is None:
            return None
        user = User.validate(user_data)
        if not user.active:
            raise HTTPException(401, "User inactive")
        return UserWithRoles.load_groups(user, client_id)

    @staticmethod
    def load_groups(user: User, client_id: str) -> Optional['UserWithRoles']:
        if not user.active:
            raise HTTPException(401, "User inactive")
        group_data = client_user_cache_collection.find_one({
            'client_id': client_id,
            'user_id': user.id,
        })
        if group_data is None:
            group_data = _create_user_cache_for_user_client(user, client_id)
        if group_data is None:
            return None
        return UserWithRoles(user=user, roles=group_data['roles'], last_modified=group_data['last_modified'])

    @staticmethod
    async def async_load(user_id: str, client_id: str) -> Optional['UserWithRoles']:
        user_data = await async_user_collection.find_one({'_id': user_id})
        if user_data is None:
            return None
        user = User.validate(user_data)
        if not user.active:
            raise HTTPException(401, "User inactive")
        return await UserWithRoles.async_load_groups(user, client_id)

    @staticmethod
    async def async_load_groups(user: User, client_id: str) -> Optional['UserWithRoles']:
        if not user.active:
            raise HTTPException(401, "User inactive")
        group_data = await async_client_user_cache_collection.find_one({
            'client_id': client_id,
            'user_id': user.id,
        })
        if group_data is None:
            group_data = await _async_create_user_cache_for_user_client(user, client_id)
        if group_data is None:
            return None
        return UserWithRoles(user=user, roles=group_data['roles'], last_modified=group_data['last_modified'])

    @staticmethod
    async def async_load_all(client_id: str) -> AsyncIterator[User]:
        client = await async_client_collection.find_one({'_id': client_id}, {'_id': 0, 'access_groups': 1})
        if client is None:
            raise HTTPException(400, "Invalid client")

        client_groups = [access_group for access_group in client['access_groups']]
        client_user_groups = [access_group['group'] for access_group in client_groups]

        all_client_group_maps = await _async_resolve_groups(client_user_groups)
        all_client_groups = set(group for groups in all_client_group_maps.values() for group in groups)

        async for user_data in async_user_collection.find({'groups': {'$in': all_client_groups}}):
            yield User.validate(user_data)
