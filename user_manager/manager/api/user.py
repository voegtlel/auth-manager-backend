import hashlib
from datetime import datetime, timezone
from uuid import uuid4

import time
from typing import List, Dict, Any, Optional

import gridfs
from authlib.common.security import generate_token
from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.params import Header, Body, File, Query

from user_manager.common.config import config
from user_manager.common.models import DbUser, UserPropertyType, DbManagerSchema, DbUserView, DbUserHistory, DbChange
from user_manager.common.mongo import async_user_collection, async_user_picture_bucket, \
    async_client_user_cache_collection, async_user_group_collection, async_session_collection, \
    async_authorization_code_collection, async_token_collection, async_read_schema, async_user_view_collection, \
    async_user_history_collection
from user_manager.common.password_helper import create_password
from user_manager.manager.api.user_helpers import check_token, update_user as _update_user, create_token, \
    async_send_mail_reset_password, update_resend_registration
from user_manager.manager.auth import Authentication
from user_manager.manager.helper import DotDict
from user_manager.manager.models import UserListViewData, UserListProperty, \
    UserViewData, UserPropertyWithValue, PasswordInWrite, UserProperty, \
    PasswordReset, UserViewDataGroup, UsersListViewData, PasswordResetResult

router = APIRouter()


def _get_user_property_value(
        prop_key: str,
        schema: DbManagerSchema,
        user_data: dict,
        is_self: bool = False,
        is_admin: bool = False,
        is_registering: bool = False,
) -> Any:
    prop = schema.properties_by_key[prop_key]
    if prop.can_read.has_access(is_self, is_admin):
        if prop.type == UserPropertyType.password:
            return None
        if prop.type == UserPropertyType.picture:
            if prop_key in user_data and user_data[prop_key] is not None:
                return f"{config.oauth2.base_url}/picture/{user_data[prop_key]}"
            return None
        if is_registering and user_data.get(prop_key) is None and prop.default:
            return prop.default
        if prop.type == UserPropertyType.access_token:
            value = user_data.get(prop_key)
            if not value:
                return value
            return [{'id': val['id'], 'description': val['description']} for val in value]
        return user_data.get(prop_key)
    return None


async def _get_view_users(
        view_id: str,
        self_id: str,
        is_admin: bool,
) -> UsersListViewData:
    """Gets users as list."""
    schema = await async_read_schema()
    view_data = await async_user_view_collection.find_one({'_id': view_id})
    if view_data is None:
        raise HTTPException(404, f"View {view_id} not existing")
    view = DbUserView.validate_document(view_data)
    if view.filter is not None:
        users_data = async_user_collection.find(view.filter.to_mongodb())
    else:
        users_data = async_user_collection.find()
    users: List[UserListViewData] = []
    async for user_data in users_data:
        users.append(UserListViewData(
            user_id=user_data['_id'],
            properties=[
                UserListProperty(
                    key=prop,
                    value=_get_user_property_value(prop, schema, user_data, user_data['_id'] == self_id, is_admin),
                )
                for prop in view.list_properties
                if schema.properties_by_key[prop].can_read.has_access(user_data['_id'] == self_id, is_admin)
                or schema.properties_by_key[prop].can_edit.has_access(user_data['_id'] == self_id, is_admin)
            ]
        ))
    return UsersListViewData(
        view_id=view.id,
        view_name=view.name,
        properties=[
            UserProperty.validate(schema.properties_by_key[prop])
            for prop in view.list_properties
        ],
        users=users,
    )


@router.get(
    '/users/list/{view_id}',
    tags=['User Manager'],
    response_model=UsersListViewData,
)
async def get_list_users(
        view_id: str,
        user: UserInfo = Depends(Authentication())
) -> UsersListViewData:
    """Gets users as list."""
    is_admin = 'admin' in user['roles']
    return await _get_view_users(view_id, user.sub, is_admin)


async def _get_user_view(
        view_name: Optional[str],
        is_self: bool,
        is_admin: bool,
        user_data: DotDict = None,
        schema: DbManagerSchema = None,
) -> UserViewData:
    """Gets user data for creation."""
    if schema is None:
        schema = await async_read_schema()
    view_data = await async_user_view_collection.find_one({'_id': view_name})
    if view_data is None:
        raise HTTPException(400, f"Invalid view {view_name}")
    view: DbUserView = DbUserView.validate_document(view_data)

    return UserViewData(
        user_id='new' if user_data is None else user_data['_id'],
        view_groups=[
            UserViewDataGroup(
                title=prop_group.title,
                type=prop_group.type,
                properties=[
                    UserPropertyWithValue(
                        value=(
                            schema.properties_by_key[prop].default
                            if user_data is None else
                            _get_user_property_value(prop, schema, user_data, is_self, is_admin)
                        ),
                        **schema.properties_by_key[prop].dict()
                    )
                    for prop in prop_group.user_properties
                    if schema.properties_by_key[prop].can_read.has_access(is_self=is_self, is_admin=is_admin)
                    or schema.properties_by_key[prop].can_edit.has_access(is_self=is_self, is_admin=is_admin)
                ]
            )
            for prop_group in view.view_groups
        ]
    )


@router.get(
    '/users/new',
    tags=['User Manager'],
    response_model=UserViewData,
)
async def get_create_user(
    user: UserInfo = Depends(Authentication())
) -> UserViewData:
    """Gets user data for creation."""
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)

    return await _get_user_view('new', is_self=False, is_admin=is_admin)


@router.get(
    '/users/{user_id}',
    tags=['User Manager'],
    response_model=UserViewData,
)
async def get_user(
        user_id: str,
        user: UserInfo = Depends(Authentication())
) -> UserViewData:
    """Gets user data."""
    is_admin = 'admin' in user['roles']
    is_self = user.sub == user_id
    user_data = DotDict.from_obj(await async_user_collection.find_one({'_id': user_id}))
    user_data['id'] = user_data['_id']
    return await _get_user_view('all', is_self, is_admin, user_data=user_data)


@router.get(
    '/register',
    tags=['User Manager'],
    response_model=UserViewData,
)
async def get_register_user(
        token: str = Header(..., alias="x-token"),
) -> UserViewData:
    """Gets user data for registration."""
    check_token(token)
    user_data = DotDict.from_obj(await async_user_collection.find_one({
        'registration_token': token,
    }))
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    user_data['id'] = user_data['_id']
    return await _get_user_view('registration', is_self=True, is_admin=False, user_data=user_data)


@router.put(
    '/verify-email',
    tags=['User Manager'],
)
async def verify_email(
        token: str = Header(..., alias="x-token"),
):
    new_email = check_token(token)
    user_data = await async_user_collection.find_one({'email_verification_token': token})
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    updated_at = int(time.time())
    await async_user_collection.update_one({'_id': user_data['_id']}, {
        '$set': {
            'email': new_email,
            'email_verified': True,
            'updated_at': updated_at,
        },
        '$unset': {
            'email_verification_token': ""
        },
    })
    await async_client_user_cache_collection.update_many(
        {'user_id': user_data['_id']},
        {'$set': {'last_modified': updated_at}},
    )
    await async_user_history_collection.insert_one(
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_data['_id'],
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user_data['_id'],
            changes=[
                DbChange(property='email', value=new_email),
                DbChange(property='email_verified', value=True),
            ],
        ).dict(by_alias=True, exclude_none=True)
    )


@router.post(
    '/users/{user_id}/reset-password',
    tags=['User Manager'],
    response_model=PasswordResetResult,
)
async def request_reset_user_password(
    user_id: str,
    return_link: bool = Query(False),
    user: UserInfo = Depends(Authentication()),
) -> PasswordResetResult:
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)
    schema = await async_read_schema()
    user_data = DotDict.from_obj(await async_user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404, "User not found")
    if user_data.get('registration_token'):
        await update_resend_registration(user_data, schema, user.sub)
    else:
        token_valid_until = int(time.time() + config.manager.token_valid.password_reset)
        user_data['password_reset_token'] = create_token(user_data['_id'], token_valid_until)

        await async_user_collection.update_one({'_id': user_data['_id']}, {
            '$set': {
                'password_reset_token': user_data['password_reset_token']
            },
        })
        if not return_link:
            await async_send_mail_reset_password(user_data, schema, token_valid_until, author_id=user.sub)
    return PasswordResetResult(
        reset_link=f"{config.manager.frontend_base_url}/reset-password/{user_data['password_reset_token']}" if return_link else None,
    )


@router.post(
    '/reset-password',
    tags=['User Manager'],
)
async def request_reset_password(
    password_reset: PasswordReset = Body(...),
):
    user_data = DotDict.from_obj(await async_user_collection.find_one({'email': password_reset.email}))
    if user_data is None:
        return
    schema = await async_read_schema()
    if user_data.get('registration_token'):
        await update_resend_registration(user_data, schema, user_data['_id'])
    else:
        token_valid_until = int(time.time() + config.manager.token_valid.password_reset)
        user_data['password_reset_token'] = create_token(user_data['_id'], token_valid_until)

        await async_user_collection.update_one({'_id': user_data['_id']}, {
            '$set': {
                'password_reset_token': user_data['password_reset_token']
            },
        })
        await async_send_mail_reset_password(user_data, schema, token_valid_until)


@router.put(
    '/reset-password',
    tags=['User Manager'],
)
async def reset_password(
        token: str = Header(..., alias="x-token"),
        password_data: PasswordInWrite = Body(...),
):
    check_token(token)
    user_data = await async_user_collection.find_one({'password_reset_token': token})
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    new_hash = create_password(password_data.password)
    updated_at = int(time.time())
    await async_user_collection.update_one({'_id': user_data['_id']}, {
        '$set': {
            'password': new_hash,
            'updated_at': updated_at,
        },
        '$unset': {
            'password_reset_token': ''
        },
    })
    await async_client_user_cache_collection.update_many(
        {'user_id': user_data['_id']},
        {'$set': {'last_modified': updated_at}},
    )
    await async_user_history_collection.insert_one(
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_data['_id'],
            timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
            author_id=user_data['_id'],
            changes=[
                DbChange(property='password', value="Set from reset token"),
            ],
        ).dict(by_alias=True, exclude_none=True)
    )


@router.put(
    '/register',
    tags=['User Manager'],
)
async def save_register_user(
        token: str = Header(..., alias="x-token"),
        update_data: Dict[str, Any] = Body(...),
):
    """Finish registration."""
    check_token(token)
    user_data = DotDict.from_obj(await async_user_collection.find_one({
        'registration_token': token,
    }))
    if user_data is None:
        raise HTTPException(401, "Invalid token")
    del user_data['registration_token']
    await _update_user(user_data, update_data, user_data['_id'], is_registering=True, is_self=True)


@router.post(
    '/users',
    tags=['User Manager'],
    status_code=201,
)
async def create_user(
        no_registration: bool = Query(False),
        create_data: Dict[str, Any] = Body(...),
        user: UserInfo = Depends(Authentication())
):
    """Updates user data."""
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)

    user_data = DotDict()
    await _update_user(user_data, create_data, user.sub, is_new=True, is_admin=True, no_registration=no_registration)


@router.patch(
    '/users/{user_id}',
    tags=['User Manager']
)
async def update_user(
        user_id: str,
        update_data: Dict[str, Any] = Body(...),
        user: UserInfo = Depends(Authentication())
):
    """Updates user data."""
    is_admin = 'admin' in user['roles']
    is_self = user.sub == user_id
    if not is_self and not is_admin:
        raise HTTPException(401)
    user_data = DotDict.from_obj(await async_user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404)
    if not update_data:
        return
    await _update_user(user_data, update_data, user.sub, is_admin=is_admin, is_self=is_self)


@router.post(
    '/users/{user_id}/reverify-email',
    tags=['User Manager']
)
async def reverify_email(
        user_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Updates user data."""
    is_admin = 'admin' in user['roles']
    is_self = user.sub == user_id
    if not is_self and not is_admin:
        raise HTTPException(401)
    user_data = DotDict.from_obj(await async_user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404)
    user_data['email_verified'] = False
    await _update_user(user_data, {'email': user_data['email']}, user.sub, is_admin=is_admin, is_self=is_self)


@router.post(
    '/users/{user_id}/resend-registration',
    tags=['User Manager']
)
async def resend_registration(
        user_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Sends the registration token email again."""
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)
    user_data = DotDict.from_obj(await async_user_collection.find_one({'_id': user_id}))
    if user_data is None:
        raise HTTPException(404)
    await update_resend_registration(user_data, await async_read_schema(), user.sub)


@router.post(
    '/picture/{user_id}',
    tags=['User Manager'],
    status_code=201,
)
async def upload_picture(
        user_id: str,
        file: UploadFile = File(..., media_type='application/octet-stream'),
        user: UserInfo = Depends(Authentication(auto_error=False)),
        registration_token: Optional[str] = Header(None, alias="x-token"),
):
    """Uploads a new picture for the passed user."""
    if user is not None:
        is_admin = 'admin' in user['roles']
        is_self = user.sub == user_id
        if not is_self or not is_admin:
            raise HTTPException(401)
        user_data = await async_user_collection.find_one({'_id': user_id})
    elif registration_token is not None:
        check_token(registration_token)
        user_data = await async_user_collection.find_one({'registration_token': registration_token})
    else:
        raise HTTPException(401)
    if user_data is None:
        raise HTTPException(404)
    mod_user = DbUser.validate_document(user_data)
    await async_user_history_collection.insert_one(DbUserHistory(
        id=str(uuid4()),
        user_id=mod_user.id,
        timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
        author_id=user.sub,
        changes=[DbChange(property='picture', value='Set')]
    ).dict(by_alias=True, exclude_none=True))
    if mod_user.picture is None:
        mod_user.picture = generate_token(48)
        updated_at = int(time.time())
        await async_user_collection.update_one(
            {'_id': user_id},
            {'$set': {
                'picture': mod_user.picture,
                'updated_at': updated_at
            }}
        )
        await async_client_user_cache_collection.update_many(
            {'user_id': user_data['_id']},
            {'$set': {'last_modified': updated_at}},
        )
    else:
        try:
            await async_user_picture_bucket.delete(mod_user.picture)
        except gridfs.errors.NoFile:
            pass
    hash_ = hashlib.sha512()
    while True:
        chunk = await file.read(4 * 1024)
        if not chunk:
            break
        hash_.update(chunk)
    await file.seek(0)
    file.file.seek(0)
    await async_user_picture_bucket.upload_from_stream_with_id(
        mod_user.picture, mod_user.id, file.file, metadata={'content_type': file.content_type, 'hash': hash_.digest()}
    )


@router.delete(
    '/users/{user_id}',
    tags=['User Manager']
)
async def remove_user(
    user_id: str,
    user: UserInfo = Depends(Authentication()),
):
    if 'admin' not in user['roles']:
        raise HTTPException(401)
    result = await async_user_collection.delete_one({'_id': user_id})
    if result.deleted_count != 1:
        raise HTTPException(404, "User does not exist")
    if user.picture:
        try:
            await async_user_picture_bucket.delete(user.picture)
        except gridfs.errors.NoFile:
            pass
    await async_session_collection.delete_many({'user_id': user_id})
    await async_authorization_code_collection.delete_many({'user_id': user_id})
    await async_token_collection.delete_many({'user_id': user_id})
    await async_user_group_collection.update_many(
        {'members': user_id},
        {
            '$pull': {
                'members': user_id,
                'email_forward_members': user_id,
                'email_allowed_forward_members': user_id,
                'email_postbox_access_members': user_id,
            }
        }
    )
    await async_client_user_cache_collection.delete_many({'user_id': user_id})
