import hashlib
import os
import time
from typing import List, Dict, Any

import gridfs
from authlib.common.security import generate_token
from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.params import Header, Body, File
from starlette.responses import Response

from user_manager.common.config import config, AccessType
from user_manager.common.models import User
from user_manager.common.mongo import user_collection, user_picture_bucket, user_group_collection
from user_manager.common.password_helper import create_password
from user_manager.manager.api.user_helpers import check_token, update_user as _update_user
from user_manager.manager.auth import Authentication
from user_manager.manager.helper import DotDict
from user_manager.manager.models import UsersListViewData, UserListViewData, UserListProperty, UserPropertyWithKey, \
    UserViewData, UserPropertyWithValue, PasswordInWrite

router = APIRouter()


def _get_user_property_value(prop: str, user_data: dict, is_self: bool = False, is_admin: bool = False) -> Any:
    if config.oauth2.user.properties[prop].can_read.has_access(is_self, is_admin):
        return user_data.get(prop)
    return None


@router.get(
    '/users',
    tags=['User Manager'],
    response_model=UsersListViewData,
)
def get_users(
        user: UserInfo = Depends(Authentication())
) -> UsersListViewData:
    """Gets user data."""
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)
    users_data = user_collection.find()
    users: List[UserListViewData] = []
    for user_data in users_data:
        user_data['sub'] = user_data['_id']
        if user_data.get('picture') is not None:
            user_data['picture'] = f"{config.oauth2.base_url}/picture/{user_data['picture']}"
        if 'password' in user_data:
            del user_data['password']
        users.append(UserListViewData(
            user_id=user_data['_id'],
            properties=[
                UserListProperty(
                    key=prop,
                    value=_get_user_property_value(prop, user_data, user_data['_id'] == user.sub, is_admin),
                )
                for prop in config.manager.list
                if config.oauth2.user.properties[prop].can_read.has_access(user_data['_id'] == user.sub, is_admin)
                or config.oauth2.user.properties[prop].can_edit.has_access(user_data['_id'] == user.sub, is_admin)
            ]
        ))
    return UsersListViewData(
        properties=[
            UserPropertyWithKey(
                key=prop,
                **config.oauth2.user.properties[prop].dict()
            )
            for prop in config.manager.list
        ],
        users=users,
    )


@router.get(
    '/users/new',
    tags=['User Manager'],
    response_model=UserViewData,
)
def get_create_user(
    user: UserInfo = Depends(Authentication())
) -> UserViewData:
    """Gets user data for creation."""
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)

    return UserViewData(
        user_id="new",
        properties=[
            UserPropertyWithValue(
                key=prop,
                value=None,
                **config.oauth2.user.properties[prop].dict()
            )
            for prop in config.manager.registration
            if config.oauth2.user.properties[prop].can_read.has_access(is_admin=is_admin)
            or config.oauth2.user.properties[prop].can_edit.has_access(is_admin=is_admin)
        ]
    )


@router.get(
    '/users/{user_id}',
    tags=['User Manager'],
    response_model=UserViewData,
)
def get_user(
        user_id: str,
        user: UserInfo = Depends(Authentication())
) -> UserViewData:
    """Gets user data."""
    is_admin = 'admin' in user['roles']
    is_self = user.sub == user_id
    if not is_self and not is_admin:
        raise HTTPException(401)
    user_data = DotDict.from_obj(user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404)
    user_data['sub'] = user_data['_id']
    if user_data.get('picture') is not None:
        user_data['picture'] = f"{config.oauth2.base_url}/picture/{user_data['picture']}"
    if 'password' in user_data:
        del user_data['password']
    return UserViewData(
        user_id=user_data['_id'],
        properties=[
            UserPropertyWithValue(
                key=prop,
                value=_get_user_property_value(prop, user_data, is_self, is_admin),
                **config.oauth2.user.properties[prop].dict()
            )
            for prop in config.manager.view
            if config.oauth2.user.properties[prop].can_read.has_access(is_self, is_admin)
            or config.oauth2.user.properties[prop].can_edit.has_access(is_self, is_admin)
        ]
    )


@router.get(
    '/register/{token}',
    tags=['User Manager'],
    response_model=UserViewData,
)
def get_register_user(
        token: str,
) -> UserViewData:
    """Gets user data for registration."""
    user_data = DotDict.from_obj(user_collection.find_one({
        'registration_token': token,
    }))
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    user_data['sub'] = user_data['_id']
    if user_data.get('picture') is not None:
        user_data['picture'] = f"{config.oauth2.base_url}/picture/{user_data['picture']}"
    if 'password' in user_data:
        del user_data['password']
    return UserViewData(
        user_id=user_data['_id'],
        properties=[
            UserPropertyWithValue(
                key=prop,
                value=_get_user_property_value(prop, user_data, is_self=True),
                **config.oauth2.user.properties[prop].dict()
            )
            for prop in config.manager.registration
            if config.oauth2.user.properties[prop].can_read.has_access(is_self=True)
            or config.oauth2.user.properties[prop].can_edit.has_access(is_self=True)
        ]
    )


@router.put(
    '/verify-email/{token}',
    tags=['User Manager'],
)
def verify_email(
        token: str = Header(...),
):
    new_email = check_token(token)
    user_data = user_collection.find_one({'email_verification_token': token})
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    user_collection.update_one({'_id': user_data['_id']}, {
        '$set': {
            'email': new_email,
            'email_verified': True,
            'updated_at': int(time.time()),
        },
        '$unset': {
            'email_verification_token': ""
        },
    })


@router.put(
    '/reset-password/{token}',
    tags=['User Manager'],
)
def reset_password(
        token: str = Header(...),
        password_data: PasswordInWrite = Body(...),
):
    check_token(token)
    user_data = user_collection.find_one({'reset_password_token': token})
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    new_hash = create_password(password_data.new_password)
    user_collection.update_one({'_id': user_data['_id']}, {
        '$set': {
            'password': new_hash,
            'updated_at': int(time.time()),
        },
        '$unset': {
            {'reset_password_token': ""}
        },
    })


@router.put(
    '/register/{token}',
    tags=['User Manager'],
)
def save_register_user(
        token: str,
        update_data: Dict[str, Any] = Body(...),
):
    """Gets user data for registration."""
    check_token(token)
    user_data = DotDict.from_obj(user_collection.find_one({
        'registration_token': token,
    }))
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    del user_data['registration_token']
    _update_user(user_data, update_data, is_registering=True, is_self=True)


@router.post(
    '/users',
    tags=['User Manager'],
    status_code=201,
)
def create_user(
        create_data: Dict[str, Any] = Body(...),
        user: UserInfo = Depends(Authentication())
):
    """Updates user data."""
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)

    user_data = DotDict()
    _update_user(user_data, create_data, is_new=True, is_admin=True)


@router.patch(
    '/users/{user_id}',
    tags=['User Manager']
)
def update_user(
        user_id: str,
        update_data: Dict[str, Any] = Body(...),
        user: UserInfo = Depends(Authentication())
):
    """Updates user data."""
    is_admin = 'admin' in user['roles']
    is_self = user.sub == user_id
    if not is_self and not is_admin:
        raise HTTPException(401)
    user_data = DotDict.from_obj(user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404)
    if not update_data:
        return
    _update_user(user_data, update_data, is_admin=is_admin, is_self=is_self)

    # Update the cookie state as well. A bit hacky, because it uses the oauth api.
    resp = Response()
    if is_self:
        from user_manager.oauth.api import COOKIE_KEY_STATE
        resp.set_cookie(
            key=COOKIE_KEY_STATE,
            value=str(user_data['updated_at']),
            max_age=config.oauth2.token_expiration.session,
            secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
        )
    return resp


@router.patch(
    '/users/{user_id}/reverify-email',
    tags=['User Manager']
)
def reverify_email(
        user_id: str,
        user: UserInfo = Depends(Authentication())
):
    """Updates user data."""
    is_admin = 'admin' in user['roles']
    is_self = user.sub == user_id
    if not is_self and not is_admin:
        raise HTTPException(401)
    user_data = DotDict.from_obj(user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404)
    user_data['email_verified'] = False
    _update_user(user_data, {'email': user_data['email']}, is_admin=is_admin, is_self=is_self)


@router.post(
    '/picture/{user_id}',
    tags=['User Manager'],
    status_code=201,
)
def upload_picture(
        user_id: str,
        file: UploadFile = File(..., media_type='application/octet-stream'),
        user: UserInfo = Depends(Authentication()),
):
    """Uploads a new picture for the passed user."""
    if user.sub != user_id and 'admin' not in user['roles']:
        raise HTTPException(401)
    user_data = user_collection.find_one({'_id': user_id})
    if user_data is None:
        raise HTTPException(404)
    user = User.validate(user_data)
    if user.picture is None:
        user.picture = generate_token(48)
        user_collection.update_one({'_id': user_id}, {'$set': {'picture': user.picture}})
    else:
        try:
            user_picture_bucket.delete(user.picture)
        except gridfs.errors.NoFile:
            pass
    hash_ = hashlib.sha512()
    while True:
        chunk = file.file.read(4 * 1024)
        if not chunk:
            break
        hash_.update(chunk)
    file.file.seek(0)
    user_picture_bucket.upload_from_stream_with_id(
        user.picture, user.id, file.file, metadata={'content_type': file.content_type, 'hash': hash_.digest()}
    )


@router.post(
    '/users/{user_id}/groups/{group_id}',
    tags=['User Manager']
)
def add_user_group(
        user_id: str,
        group_id: str,
        user: UserInfo = Depends(Authentication())
):
    """Add group to user."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    if user_collection.count_documents({'_id': user_id}) != 1:
        raise HTTPException(404, "User does not exist")
    if user_group_collection.count_documents({'_id': group_id}) != 1:
        raise HTTPException(404, "Group does not exist")
    user_collection.update_one({'_id': user_id}, {'$addToSet': {'groups': group_id}})
    user_group_collection.update_one({'_id': group_id}, {'$addToSet': {'members': user_id}})


@router.delete(
    '/users/{user_id}/groups/{group_id}',
    tags=['User Manager']
)
def remove_user_group(
        user_id: str,
        group_id: str,
        user: UserInfo = Depends(Authentication())
):
    """Remove group from user."""
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    if user_collection.count_documents({'_id': user_id}) != 1:
        raise HTTPException(404, "User does not exist")
    user_collection.update_one({'_id': user_id}, {'$pull': {'groups': group_id}})
    user_group_collection.update_one({'_id': group_id}, {'$pull': {'members': user_id}})
