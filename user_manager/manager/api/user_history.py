from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from user_manager.common.mongo import async_user_history_collection
from user_manager.manager.auth import Authentication
from user_manager.manager.models import UserHistoryInList

router = APIRouter()


@router.get(
    '/users/{user_id}/history',
    tags=['User Manager'],
    response_model=List[UserHistoryInList],
    dependencies=[Depends(Authentication())],
)
async def get_user_history(
        user_id: str,
        offset: Optional[int] = Query(None, gt=0),
        limit: Optional[int] = Query(None, gt=0),
) -> List[UserHistoryInList]:
    """Gets history entries for a user."""
    query = async_user_history_collection.find({'user_id': user_id}).sort({'timestamp': 1})
    if offset is not None:
        query = query.skip(offset)
    if limit is not None:
        query = query.limit(limit)
    return [UserHistoryInList.validate(view) async for view in query]
