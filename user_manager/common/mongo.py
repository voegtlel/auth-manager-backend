from typing import Type

from motor.core import AgnosticDatabase
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import OperationFailure

from user_manager.common.config import config
from .models import DbSession, DbAuthorizationCode, DbToken, DbUser, DbClient, DbUserGroup, DbClientUserCache, DbIpLoginThrottle, \
    DbManagerSchema, DbUserView, DbUserHistory
from .models.base import BaseDocument

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


def _async_collection(collection_cls: Type[BaseDocument]) -> AgnosticDatabase:
    return async_db[collection_cls.__collection_name__]


def _gridfs(bucket_name: str):
    import gridfs
    return gridfs.GridFSBucket(db, bucket_name=bucket_name, disable_md5=True)


def _async_gridfs(bucket_name: str):
    import motor.motor_asyncio
    return motor.motor_asyncio.AsyncIOMotorGridFSBucket(async_db, bucket_name=bucket_name, disable_md5=True)


session_collection = _collection(DbSession)
authorization_code_collection = _collection(DbAuthorizationCode)
token_collection = _collection(DbToken)
ip_login_throttle_collection = _collection(DbIpLoginThrottle)

client_collection = _collection(DbClient)
client_user_cache_collection = _collection(DbClientUserCache)
user_group_collection = _collection(DbUserGroup)
user_collection = _collection(DbUser)
user_view_collection = _collection(DbUserView)
user_history_collection = _collection(DbUserHistory)
user_picture_bucket = _gridfs('userPicture')

_manager_schema_collection = _collection(DbManagerSchema)


async_session_collection = _async_collection(DbSession)
async_authorization_code_collection = _async_collection(DbAuthorizationCode)
async_token_collection = _async_collection(DbToken)
async_ip_login_throttle_collection = _async_collection(DbIpLoginThrottle)

async_client_collection = _async_collection(DbClient)
async_client_user_cache_collection = _async_collection(DbClientUserCache)
async_user_group_collection = _async_collection(DbUserGroup)
async_user_collection = _async_collection(DbUser)
async_user_view_collection = _async_collection(DbUserView)
async_user_history_collection = _async_collection(DbUserHistory)
async_user_picture_bucket = _async_gridfs('userPicture')

_async_manager_schema_collection = _async_collection(DbManagerSchema)


async def async_read_schema() -> DbManagerSchema:
    return DbManagerSchema.validate(await _async_manager_schema_collection.find_one({'_id': 0}))


def read_schema() -> DbManagerSchema:
    return DbManagerSchema.validate(_manager_schema_collection.find_one({'_id': 0}))


async def async_update_schema(new_schema: DbManagerSchema, upsert: bool = False):
    await _async_manager_schema_collection.update_one(
        {'_id': 0}, new_schema.dict(exclude_none=True, by_alias=True), upsert=upsert
    )


def update_schema(new_schema: DbManagerSchema, upsert: bool = False):
    _manager_schema_collection.replace_one(
        {'_id': 0}, new_schema.dict(exclude_none=True, by_alias=True), upsert=upsert
    )
