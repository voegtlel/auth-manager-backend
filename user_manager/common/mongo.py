from typing import Type

from pymongo import MongoClient

from user_manager.common.config import config
from .models import BaseDocument, Session, AuthorizationCode, Token, User, Client, UserGroup, \
    ClientUserCache

db = MongoClient(config.mongo.uri).get_database()


def _collection(collection_cls: Type[BaseDocument]):
    if getattr(collection_cls, '__indexes__', None):
        created_indexes = db[collection_cls.__collection_name__].create_indexes(collection_cls.__indexes__)
        if created_indexes:
            print(f"Created indexes {created_indexes} for {collection_cls.__collection_name__}")
    return db[collection_cls.__collection_name__]


def _gridfs(bucket_name: str):
    import gridfs
    return gridfs.GridFSBucket(db, bucket_name=bucket_name, disable_md5=True)


session_collection = _collection(Session)
authorization_code_collection = _collection(AuthorizationCode)
token_collection = _collection(Token)

client_collection = _collection(Client)
client_user_cache_collection = _collection(ClientUserCache)
user_group_collection = _collection(UserGroup)
user_collection = _collection(User)

user_picture_bucket = _gridfs('userPicture')
