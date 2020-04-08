import time
from uuid import uuid4

from user_manager.common import mongo
from user_manager.common.config import config
from user_manager.common.models import User, UserGroup, Client, ClientUserCache
from user_manager.common.password_helper import create_password

if __name__ == '__main__':
    admin_id = "admin"

    mongo.authorization_code_collection.drop()
    mongo.session_collection.drop()
    mongo.token_collection.drop()

    mongo.client_collection.drop()
    mongo.user_group_collection.drop()
    mongo.user_collection.drop()
    mongo.client_user_cache_collection.drop()

    mongo.client_collection.insert_one(Client(
        id=config.manager.oauth2.client_id,
        token_endpoint_auth_method=['none'],
        redirect_uri=[config.manager.frontend_base_url],
        allowed_scope=['openid', 'profile', 'email', 'offline_access'],
        response_type=['token', 'code'],
        grant_type=['authorization_code', 'refresh_token'],
        access_groups=['admin'],
    ).dict(exclude_none=True, by_alias=True))
    mongo.user_group_collection.insert_one(UserGroup(
        id='admin',
        group_name="Admins",
        members=[admin_id],
    ).dict(exclude_none=True, by_alias=True))
    mongo.user_collection.insert_one(User(
        id=admin_id,
        email="admin@localhost",
        password=create_password('blablabla'),
        is_new=False,
        mail_verified=True,
        name="Admin",
        family_name="Admin",
        given_name="Admin",
        groups=['admin'],
    ).dict(exclude_none=True, by_alias=True))
    mongo.client_user_cache_collection.insert_one(ClientUserCache(
        id=uuid4().hex,
        client_id=config.manager.oauth2.client_id,
        user_id=admin_id,
        groups=['admin'],
        last_modified=int(time.time()),
    ).dict(exclude_none=True, by_alias=True))
