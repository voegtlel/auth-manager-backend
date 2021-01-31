import time

from authlib.common.security import generate_token

from user_manager import default_schema
from user_manager.common import mongo
from user_manager.common.config import config
from user_manager.common.models import DbUser, DbUserGroup, DbClient, DbAccessGroup
from user_manager.common.mongo import update_schema
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
    mongo.user_history_collection.drop()
    mongo.user_view_collection.drop()

    now = int(time.time())

    update_schema(default_schema.default_schema, upsert=True)
    mongo.user_view_collection.insert_many([
        view.dict(exclude_none=True, by_alias=True) for view in default_schema.default_views
    ])

    mongo.client_collection.insert_one(DbClient(
        id=config.manager.oauth2.client_id,
        token_endpoint_auth_method=['none'],
        redirect_uri=[config.manager.frontend_base_url],
        allowed_scope=['openid', 'profile', 'email', 'offline_access'],
        response_type=['token', 'code'],
        grant_type=['authorization_code', 'refresh_token'],
        access_groups=[DbAccessGroup(group='admin', roles=['admin']), DbAccessGroup(group='users', roles=['edit_self'])],
    ).dict(exclude_none=True, by_alias=True))
    mongo.user_group_collection.insert_one(DbUserGroup(
        id='users',
        visible=False,
        group_name="All Users",
        members=[admin_id],
        group_type="management",
    ).dict(exclude_none=True, by_alias=True))
    mongo.user_group_collection.insert_one(DbUserGroup(
        id='admin',
        visible=False,
        group_name="Admins",
        members=[admin_id],
        group_type="management",
    ).dict(exclude_none=True, by_alias=True))
    registration_token = create_token(admin_id, now + config.manager.token_valid.registration)
    mongo.user_collection.insert_one(DbUser(
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
