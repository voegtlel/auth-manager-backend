from datetime import datetime
from typing import Optional

from user_manager.common.models import DbUser, DbSession
from user_manager.common.mongo import async_session_collection, async_user_collection, session_collection, \
    user_collection


def validate_session(sid: Optional[str]) -> Optional[DbUser]:
    if sid is None:
        return None
    session_data = session_collection.find_one({'_id': sid})
    if session_data is None:
        return None
    session = DbSession.validate_document(session_data)
    if session.expiration_time < datetime.utcnow():
        return None
    user_data = user_collection.find_one({'_id': session.user_id})
    if user_data is None:
        return None
    return DbUser.validate_document(user_data)


async def async_validate_session(sid: Optional[str]) -> Optional[DbUser]:
    if sid is None:
        return None
    session_data = await async_session_collection.find_one({'_id': sid})
    if session_data is None:
        return None
    session = DbSession.validate_document(session_data)
    if session.expiration_time < datetime.utcnow():
        return None
    user_data = await async_user_collection.find_one({'_id': session.user_id})
    if user_data is None:
        return None
    return DbUser.validate_document(user_data)
