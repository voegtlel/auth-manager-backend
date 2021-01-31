from typing import List
from uuid import UUID

from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from fastapi.params import Body

from user_manager.common.models import DbUserView, DbUserFilter, DbUserViewGroup
from user_manager.common.mongo import async_user_view_collection
from user_manager.manager.auth import Authentication
from user_manager.manager.models import UserViewInList, UserViewInWrite, UserViewInRead

router = APIRouter()


@router.get(
    '/schema/views',
    tags=['User Manager'],
    response_model=List[UserViewInList],
    dependencies=[Depends(Authentication())],
)
async def get_views() -> List[UserViewInList]:
    """Gets all views."""
    return [
        UserViewInList.validate(view)
        async for view in async_user_view_collection.find()
    ]


@router.get(
    '/schema/views/{view_id}',
    tags=['User Manager'],
    response_model=UserViewInRead,
    dependencies=[Depends(Authentication())],
)
async def get_view(view_id: UUID) -> UserViewInRead:
    """Gets one view."""
    user_view_data = await async_user_view_collection.find_one({'_id': view_id})
    if user_view_data is None:
        raise HTTPException(404, f"View {view_id} not found")
    return UserViewInRead.validate(user_view_data)


@router.get(
    '/groups/{group_id}/views',
    tags=['User Manager'],
    response_model=UserViewInRead,
    dependencies=[Depends(Authentication())],
)
async def get_view(group_id: str) -> UserViewInRead:
    """Gets one view by the group id."""
    user_view_data = await async_user_view_collection.find_one({'group_id': group_id})
    if user_view_data is None:
        raise HTTPException(404, f"View for group {group_id} not found")
    return UserViewInRead.validate(user_view_data)


@router.put(
    '/schema/views/{view_id}',
    tags=['User Manager'],
)
async def update_view(
    view_id: UUID,
    view: UserViewInWrite = Body(...),
    user: UserInfo = Depends(Authentication()),
):
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)
    user_view_data = await async_user_view_collection.find_one({'_id': view_id})
    if user_view_data is None:
        raise HTTPException(404, f"View {view_id} not found")
    db_user_view = DbUserView.validate(user_view_data)

    db_user_view.name = view.name
    db_user_view.filter = (None if view.filter is None else DbUserFilter.validate(view.filter))
    db_user_view.list_properties = view.list_properties
    db_user_view.view_groups = [
        DbUserViewGroup(
            type=view_group.type,
            title=view_group.title,
            user_properties=view_group.user_properties
        )
        for view_group in view.view_groups
    ]
    await async_user_view_collection.replace_one({'_id': view_id}, db_user_view.dict(exclude_none=True, by_alias=True))
