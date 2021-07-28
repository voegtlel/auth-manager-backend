from datetime import datetime, timezone
from typing import List, Sequence, Union, Dict
from uuid import uuid4

import time
from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from fastapi.params import Body

from user_manager.common.models import DbUserGroup, DbUserHistory, DbChange
from user_manager.common.mongo import async_user_group_collection, \
    async_client_user_cache_collection, async_user_collection, \
    async_client_collection, async_user_history_collection
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
        GroupInList.validate(DbUserGroup.validate_document(group))
        async for group in async_user_group_collection.find(group_filter)
    ]


async def _merge_update_user_history(history_entries: List[DbUserHistory]):
    if history_entries:
        history_entries_by_uid: Dict[str, DbUserHistory] = {}
        for entry in history_entries:
            if entry.user_id in history_entries_by_uid:
                history_entries_by_uid[entry.user_id].changes.extend(entry.changes)
            else:
                history_entries_by_uid[entry.user_id] = entry
        await async_user_history_collection.insert_many([
            entry.dict(by_alias=True, exclude_none=True)
            for entry in history_entries_by_uid.values()
        ])


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
    new_group = DbUserGroup.validate_override(group_data)
    new_group.id = new_group.id.lower()
    if not new_group.enable_email:
        new_group.email_forward_members = []
        new_group.email_allowed_forward_members = []
    if not new_group.enable_postbox:
        new_group.email_postbox_access_members = []
    await async_user_group_collection.insert_one(new_group.document())
    timestamp = int(time.time())
    history_entries: List[DbUserHistory] = []
    if new_group.members:
        await async_client_user_cache_collection.delete_many({'user_id': {'$in': new_group.members}})
        await async_user_collection.update_many(
            {'_id': {'$in': new_group.members}},
            {
                '$addToSet': {'groups': new_group.id},
                '$set': {'updated_at': timestamp},
            }
        )
        history_entries.extend(DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='groups', value=f'Added {new_group.id}')],
        ) for user_id in new_group.members)
    if new_group.email_forward_members:
        await async_user_collection.update_many(
            {'_id': {'$in': new_group.email_forward_members}},
            {
                '$addToSet': {'email_forward_groups': new_group.id},
                '$set': {'updated_at': timestamp},
            }
        )
        history_entries.extend(DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='email_forward_groups', value=f'Added {new_group.id}')],
        ) for user_id in new_group.email_forward_members)
    if new_group.email_allowed_forward_members:
        await async_user_collection.update_many(
            {'_id': {'$in': new_group.email_allowed_forward_members}},
            {
                '$addToSet': {'email_allowed_forward_groups': new_group.id},
                '$set': {'updated_at': timestamp},
            }
        )
        history_entries.extend(DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='email_allowed_forward_groups', value=f'Added {new_group.id}')],
        ) for user_id in new_group.email_allowed_forward_members)
    if new_group.email_postbox_access_members:
        await async_user_collection.update_many(
            {'_id': {'$in': new_group.email_postbox_access_members}},
            {
                '$addToSet': {'email_postbox_access_groups': new_group.id},
                '$set': {'updated_at': timestamp},
            }
        )
        history_entries.extend(DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='email_postbox_access_groups', value=f'Added {new_group.id}')],
        ) for user_id in new_group.email_postbox_access_members)

    await _merge_update_user_history(history_entries)


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
    return GroupInRead.validate(DbUserGroup.validate_document(group_data))


async def _update_groups(
        group: DbUserGroup,
        group_update: Union[DbUserGroup, GroupInWrite],
        author_id: str,
        history_entries: List[DbUserHistory],
        attr_name: str,
        add_user_attr_name: str,
        pull_user_attr_names: Sequence[str],
        pull_group_attr_names: Sequence[str] = (),
        clear_cache: bool = False,
):
    group_set = set(getattr(group, attr_name))
    update_set = set(getattr(group_update, attr_name))
    if group_set != update_set:
        added_users = update_set
        added_users.difference_update(getattr(group, attr_name))
        removed_users = group_set
        removed_users.difference_update(getattr(group_update, attr_name))
        changed_users = added_users | removed_users
        timestamp = int(time.time())
        if clear_cache:
            await async_client_user_cache_collection.delete_many({'user_id': {'$in': list(changed_users)}})
        else:
            await async_client_user_cache_collection.update_many(
                {'user_id': {'$in': list(changed_users)}}, {'$set': {'last_modified': timestamp}}
            )
        if added_users:
            await async_user_collection.update_many(
                {'_id': {'$in': list(added_users)}},
                {
                    '$addToSet': {add_user_attr_name: group.id},
                    '$set': {'updated_at': timestamp},
                }
            )
            history_entries.extend(
                DbUserHistory(
                    id=str(uuid4()),
                    user_id=user_id,
                    timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
                    author_id=author_id,
                    changes=[DbChange(property=add_user_attr_name, value=f'Added {group.id}')],
                )
                for user_id in added_users
            )
        if removed_users:
            await async_user_collection.update_many(
                {'_id': {'$in': list(removed_users)}},
                {
                    '$pull': {
                        attr: group.id
                        for attr in pull_user_attr_names
                    },
                    '$set': {'updated_at': timestamp},
                }
            )
            history_entries.extend(
                DbUserHistory(
                    id=str(uuid4()),
                    user_id=user_id,
                    timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
                    author_id=author_id,
                    changes=[DbChange(property=attr, value=f'Removed {group.id}')],
                )
                for user_id in removed_users
                for attr in pull_user_attr_names
            )
            for attr in pull_group_attr_names:
                group_attr = getattr(group, attr)
                for removed_user in removed_users:
                    try:
                        group_attr.remove(removed_user)
                    except ValueError:
                        pass


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
    group = DbUserGroup.validate_document(group_data)

    if not group_update.enable_email:
        group_update.email_forward_members = []
        group_update.email_allowed_forward_members = []
    if not group_update.enable_postbox:
        group_update.email_postbox_access_members = []

    history_entries = []

    await _update_groups(
        group,
        group_update,
        author_id=user.sub,
        history_entries=history_entries,
        attr_name='members',
        add_user_attr_name='groups',
        pull_user_attr_names=('groups', 'email_forward_groups', 'email_allowed_forward_groups'),
        pull_group_attr_names=(
            'email_forward_members', 'email_allowed_forward_members', 'email_postbox_access_members'
        ),
        clear_cache=True,
    )
    await _update_groups(
        group,
        group_update,
        author_id=user.sub,
        history_entries=history_entries,
        attr_name='email_allowed_forward_members',
        add_user_attr_name='email_allowed_forward_groups',
        pull_user_attr_names=('email_forward_groups', 'email_allowed_forward_groups'),
        pull_group_attr_names=('email_forward_members',),
        clear_cache=False,
    )
    await _update_groups(
        group,
        group_update,
        author_id=user.sub,
        history_entries=history_entries,
        attr_name='email_forward_members',
        add_user_attr_name='email_forward_groups',
        pull_user_attr_names=('email_forward_groups',),
        clear_cache=False,
    )
    await _update_groups(
        group,
        group_update,
        author_id=user.sub,
        history_entries=history_entries,
        attr_name='email_postbox_access_members',
        add_user_attr_name='email_postbox_access_groups',
        pull_user_attr_names=('email_postbox_access_groups',),
        clear_cache=False,
    )

    await _merge_update_user_history(history_entries)

    group.update_from(group_update)
    result = await async_user_group_collection.replace_one(
        {'_id': group_id},
        group.document(),
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
            '$pull': {
                'groups': group_id,
                'email_forward_groups': group_id,
                'email_allowed_forward_groups': group_id,
                'email_postbox_access_groups': group_id,
            },
            '$set': {'updated_at': int(time.time())},
        }
    )
    await async_client_collection.update_many(
        {'access_groups.group': group_id},
        {'$pull': {'access_groups': {'group': group_id}}},
    )
    await async_client_user_cache_collection.delete_many({'groups': group_id})
    await async_user_group_collection.update_many(
        {'member_groups': group_id},
        {'$pull': {
            'member_groups': group_id,
        }}
    )
    delete_group_data = await async_user_group_collection.find_one({'_id': group_id})
    if delete_group_data is None:
        raise HTTPException(404)
    delete_group = DbUserGroup.validate_document(delete_group_data)
    await _merge_update_user_history([
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='groups', value=f'Removed {delete_group.id}')],
        )
        for user_id in delete_group.members
    ] + [
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='email_forward_groups', value=f'Removed {delete_group.id}')],
        )
        for user_id in delete_group.email_forward_members
    ] + [
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='email_allowed_forward_groups', value=f'Removed {delete_group.id}')],
        )
        for user_id in delete_group.email_allowed_forward_members
    ] + [
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_id,
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user.sub,
            changes=[DbChange(property='email_postbox_access_groups', value=f'Removed {delete_group.id}')],
        )
        for user_id in delete_group.email_postbox_access_members
    ])
    result = await async_user_group_collection.delete_one({'_id': group_id})
    if result.deleted_count != 1:
        raise HTTPException(404)
