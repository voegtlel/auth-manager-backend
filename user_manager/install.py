import time

from authlib.common.security import generate_token

from user_manager.common import mongo
from user_manager.common.config import config
from user_manager.common.models import User, UserGroup, Client, AccessGroup
from user_manager.manager.api.user_helpers import create_token

if __name__ == '__main__':
    admin_id = generate_token(48)

    mongo.authorization_code_collection.drop()
    mongo.session_collection.drop()
    mongo.token_collection.drop()
    mongo.ip_login_throttle_collection.drop()

    mongo.client_collection.drop()
    mongo.user_group_collection.drop()
    mongo.user_collection.drop()
    mongo.client_user_cache_collection.drop()

    now = int(time.time())

    mongo.client_collection.insert_one(Client(
        id=config.manager.oauth2.client_id,
        token_endpoint_auth_method=['none'],
        redirect_uri=[config.manager.frontend_base_url],
        allowed_scope=['openid', 'profile', 'email', 'offline_access'],
        response_type=['token', 'code'],
        grant_type=['authorization_code', 'refresh_token'],
        access_groups=[AccessGroup(group='admin', roles=['admin']), AccessGroup(group='users', roles=['edit_self'])],
    ).dict(exclude_none=True, by_alias=True))
    mongo.user_group_collection.insert_one(UserGroup(
        id='users',
        visible=False,
        group_name="All Users",
        members=[admin_id],
    ).dict(exclude_none=True, by_alias=True))
    mongo.user_group_collection.insert_one(UserGroup(
        id='admin',
        visible=False,
        group_name="Admins",
        members=[admin_id],
    ).dict(exclude_none=True, by_alias=True))
    registration_token = create_token(admin_id, now + config.manager.token_valid.registration)
    mongo.user_collection.insert_one(User(
        id=admin_id,
        email="admin@localhost",
        active=False,
        email_verified=True,
        groups=['users', 'admin'],
        updated_at=now,
        registration_token=registration_token,
    ).dict(exclude_none=True, by_alias=True))
    print("Use the following link to register the administrator:")
    print(f"{config.manager.frontend_base_url}/register/{registration_token}")
