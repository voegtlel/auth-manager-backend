import time
from typing import List

from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from fastapi.params import Body

from user_manager.common.models import UserGroup
from user_manager.common.mongo import async_user_group_collection, \
    async_client_user_cache_collection, async_user_collection, \
    async_client_collection
from user_manager.manager.auth import Authentication
from user_manager.manager.models import GroupInRead, GroupInCreate, GroupInWrite, GroupInList

router = APIRouter()


@router.get(
    '/groups',
    tags=['User Manager'],
    response_model=List[GroupInList],
)
async def get_groups(
        user: UserInfo = Depends(Authentication()),
) -> List[GroupInList]:
    """Gets all groups."""
    if 'admin' in user['roles']:
        group_filter = {}
    else:
        group_filter = {'visible': True}
    return [
        GroupInList.validate(UserGroup.validate(group))
        async for group in async_user_group_collection.find(group_filter)
    ]


@router.post(
    '/groups',
    tags=['User Manager'],
    status_code=201
)
async def create_group(
        group_data: GroupInCreate = Body(...),
        user: UserInfo = Depends(Authentication()),
):
    """Creates a group."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    new_group = UserGroup.validate(group_data)
    await async_user_group_collection.insert_one(new_group.dict(exclude_none=True, by_alias=True))
    if new_group.members:
        await async_client_user_cache_collection.delete_many({'user_id': {'$in': new_group.members}})
        await async_user_collection.update_many(
            {'_id': {'$in': new_group.members}},
            {
                '$addToSet': {'groups': new_group.id},
                '$set': {'updated_at': int(time.time())},
            }
        )


@router.get(
    '/groups/{group_id}',
    tags=['User Manager'],
)
async def get_group(
        group_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Gets a group."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    group_data = await async_user_group_collection.find_one({'_id': group_id})
    if group_data is None:
        raise HTTPException(404)
    return GroupInRead.validate(UserGroup.validate(group_data))


@router.put(
    '/groups/{group_id}',
    tags=['User Manager'],
)
async def update_group(
        group_id: str,
        group_update: GroupInWrite,
        user: UserInfo = Depends(Authentication()),
):
    """Updates a group."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    group_data = await async_user_group_collection.find_one({'_id': group_id})
    if group_data is None:
        raise HTTPException(404)

    group = UserGroup.validate(group_data)
    if set(group.members) != set(group_update.members):
        added_users = set(group_update.members)
        added_users.difference_update(group.members)
        removed_users = set(group.members)
        removed_users.difference_update(group_update.members)
        changed_users = added_users | removed_users
        await async_client_user_cache_collection.delete_many({'user_id': {'$in': list(changed_users)}})
        await async_client_user_cache_collection.delete_many({'groups': group_id})
        if added_users:
            await async_user_collection.update_many(
                {'_id': {'$in': list(added_users)}},
                {
                    '$addToSet': {'groups': group_id},
                    '$set': {'updated_at': int(time.time())},
                }
            )
        if removed_users:
            await async_user_collection.update_many(
                {'_id': {'$in': list(removed_users)}},
                {
                    '$pull': {'groups': group_id},
                    '$set': {'updated_at': int(time.time())},
                }
            )
    group.member_groups = group_update.member_groups
    group.members = group_update.members
    group.group_name = group_update.group_name
    group.visible = group_update.visible
    group.notes = group_update.notes
    result = await async_user_group_collection.replace_one(
        {'_id': group_id},
        group.dict(exclude_none=True, by_alias=True),
    )
    if result.matched_count != 1:
        raise HTTPException(404)


@router.delete(
    '/groups/{group_id}',
    tags=['User Manager'],
)
async def delete_group(
        group_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Deletes a group."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    await async_user_collection.update_many(
        {'groups': group_id},
        {
            '$pull': {'groups': group_id},
            '$set': {'updated_at': int(time.time())},
        }
    )
    await async_client_collection.update_many(
        {'access_groups.group': group_id},
        {'$pull': {'access_groups': {'group': group_id}}},
    )
    await async_client_user_cache_collection.delete_many({'groups': group_id})
    await async_user_group_collection.update_many({'member_groups': group_id}, {'$pull': {'member_groups': group_id}})
    result = await async_user_group_collection.delete_one({'_id': group_id})
    if result.deleted_count != 1:
        raise HTTPException(404)
