from typing import Type

from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import OperationFailure

from user_manager.common.config import config
from .models import BaseDocument, Session, AuthorizationCode, Token, User, Client, UserGroup, \
    ClientUserCache, IpLoginThrottle

db = MongoClient(config.mongo.uri).get_database()

async_db = AsyncIOMotorClient(config.mongo.uri).get_database()


def _collection(collection_cls: Type[BaseDocument]):
    if getattr(collection_cls, '__indexes__', None):
        try:
            created_indexes = db[collection_cls.__collection_name__].create_indexes(collection_cls.__indexes__)
            if created_indexes:
                print(f"Created indexes {created_indexes} for {collection_cls.__collection_name__}")
        except OperationFailure:
            db[collection_cls.__collection_name__].drop_indexes()
            created_indexes = db[collection_cls.__collection_name__].create_indexes(collection_cls.__indexes__)
            if created_indexes:
                print(f"Recreated indexes {created_indexes} for {collection_cls.__collection_name__}")

    return db[collection_cls.__collection_name__]


def _async_collection(collection_cls: Type[BaseDocument]):
    return async_db[collection_cls.__collection_name__]


def _gridfs(bucket_name: str):
    import gridfs
    return gridfs.GridFSBucket(db, bucket_name=bucket_name, disable_md5=True)


def _async_gridfs(bucket_name: str):
    import motor.motor_asyncio
    return motor.motor_asyncio.AsyncIOMotorGridFSBucket(async_db, bucket_name=bucket_name, disable_md5=True)


session_collection = _collection(Session)
authorization_code_collection = _collection(AuthorizationCode)
token_collection = _collection(Token)
ip_login_throttle_collection = _collection(IpLoginThrottle)

client_collection = _collection(Client)
client_user_cache_collection = _collection(ClientUserCache)
user_group_collection = _collection(UserGroup)
user_collection = _collection(User)


user_picture_bucket = _gridfs('userPicture')


async_session_collection = _async_collection(Session)
async_authorization_code_collection = _async_collection(AuthorizationCode)
async_token_collection = _async_collection(Token)
async_ip_login_throttle_collection = _async_collection(IpLoginThrottle)

async_client_collection = _async_collection(Client)
async_client_user_cache_collection = _async_collection(ClientUserCache)
async_user_group_collection = _async_collection(UserGroup)
async_user_collection = _async_collection(User)

async_user_picture_bucket = _async_gridfs('userPicture')
