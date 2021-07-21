import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from uuid import uuid4

import sys
import time
from typing import Iterator, List, Optional, Any

from authlib.common.security import generate_token
from pydantic.main import BaseModel

from user_manager.common import mongo
from user_manager.common.models import DbUserGroup, DbUser, DbUserHistory, DbChange
from user_manager.common.mongo import user_history_collection
from user_manager.manager.api.user_helpers import normalize_username


def pip_install(package: str):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


class UserData(BaseModel):
    uid: str
    display_name: Optional[str]
    password: Optional[str]
    address: Optional[str]
    email: Optional[str]
    email_verified: bool
    phone: Optional[str]
    language: Optional[str]
    timezone: Optional[str]
    groups: List[str]


class GroupData(BaseModel):
    gid: str
    display_name: str
    members: List[str]


class DatabaseReader:
    prefix: str

    def _make_cursor(self) -> Any:
        pass

    def read_users(self) -> Iterator[UserData]:
        user_cursor = self._make_cursor()
        query = (
            f"SELECT users.uid, users.displayname, users.password, accounts.data FROM {self.prefix}users as users "
            f"LEFT JOIN {self.prefix}accounts as accounts ON accounts.uid = users.uid"
        )
        user_cursor.execute(query)

        preferences_cursor = self._make_cursor()
        preferences_query = (
            f"SELECT appid, configkey, configvalue FROM {self.prefix}preferences WHERE userid=%s"
        )

        groups_cursor = self._make_cursor()
        groups_query = (
            f"SELECT gid FROM {self.prefix}group_user WHERE uid = %s"
        )

        for uid, displayname, password, data in user_cursor:
            account = json.loads(data)
            preferences_cursor.execute(preferences_query, (uid,))
            if password and len(password) > 2 and password[1] == '|':
                password = password[2:]
            groups_cursor.execute(groups_query, (uid,))
            groups = [gid.lower() for gid, in groups_cursor]
            profile = UserData(
                uid=uid,
                display_name=displayname or account.get('displayname', {}).get('value'),
                password=password,
                address=account.get('address', {}).get('value'),
                email=account.get('email', {}).get('value'),
                email_verified=account.get('email', {}).get('verified', "0") != "0",
                phone=account.get('phone', {}).get('value'),
                groups=groups,
            )
            for appid, configkey, configvalue in preferences_cursor:
                if (appid, configkey) == ('core', 'timezone'):
                    profile.timezone = configvalue
                elif (appid, configkey) == ('core', 'lang'):
                    profile.language = configvalue
                elif (appid, configkey) == ('settings', 'email') and configvalue is not None:
                    profile.email = configvalue
            yield profile
        groups_cursor.close()
        preferences_cursor.close()
        user_cursor.close()

    def read_groups(self) -> Iterator[GroupData]:
        group_cursor = self._make_cursor()
        query = (
            f"SELECT gid, displayname FROM {self.prefix}groups"
        )
        group_cursor.execute(query)

        member_cursor = self._make_cursor()
        member_query = (
            f"SELECT uid FROM {self.prefix}group_user WHERE gid = %s"
        )

        for gid, displayname in group_cursor:
            member_cursor.execute(member_query, (gid,))
            members = [uid for uid, in member_cursor]
            yield GroupData(gid=gid, display_name=displayname, members=members)
        group_cursor.close()
        member_cursor.close()


class DatabaseReaderMysql(DatabaseReader):
    def __init__(self, args):
        pip_install('mysql-connector-python')
        import mysql.connector

        self.connection = mysql.connector.connect(
            database=args.dbname, host=args.dbhost, port=args.dbport, user=args.dbuser, password=args.dbpassword
        )

        self.prefix = args.dbtableprefix

    def _make_cursor(self) -> Any:
        return self.connection.cursor(buffered=True)


class DatabaseReaderPostgres:
    def __init__(self, args):
        pip_install('psycopg2')
        import psycopg2

        self.connection = psycopg2.connect(
            database=args.dbname, host=args.dbhost, port=args.dbport, user=args.dbuser, password=args.dbpassword
        )

        self.prefix = args.dbtableprefix

    def _make_cursor(self) -> Any:
        return self.connection.cursor()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(__file__)
    parser.add_argument(
        '--dbtype',
        type=str,
        choices=['mysql', 'pgsql'],
        help="or use environment variable DB_TYPE",
        default=os.environ.get('DB_TYPE', 'mysql'),
    )
    parser.add_argument(
        '--dbname',
        type=str,
        help="or use environment variable DB_NAME",
        default=os.environ.get('DB_NAME', 'nextcloud'),
    )
    parser.add_argument(
        '--dbhost',
        type=str,
        help="or use environment variable DB_HOST",
        default=os.environ.get('DB_HOST', 'localhost'),
    )
    parser.add_argument(
        '--dbport',
        type=int,
        help="or use environment variable DB_PORT",
        default=os.environ.get('DB_PORT', 3306),
    )
    parser.add_argument(
        '--dbuser',
        type=str,
        help="or use environment variable DB_USER",
        default=os.environ.get('DB_USER', 'root'),
    )
    parser.add_argument(
        '--dbpassword',
        type=str,
        help="or use environment variable DB_PASSWORD",
        default=os.environ.get('DB_PASSWORD'),
    )
    parser.add_argument(
        '--dbtableprefix',
        type=str,
        help="or use environment variable DB_TABLE_PREFIX",
        default=os.environ.get('DB_TABLE_PREFIX', 'oc_'),
    )

    parser.add_argument(
        '--keep-ids',
        action='store_true',
        help="... or use environment variable KEEP_IDS='1'. If provided, keep the existing user ids.",
        default=os.environ.get('KEEP_IDS', '0') == '1',
    )

    args = parser.parse_args()

    if args.dbtype == 'mysql':
        reader = DatabaseReaderMysql(args)
    elif args.dbtype == 'pgsql':
        reader = DatabaseReaderPostgres(args)
    else:
        parser.print_usage()
        exit(-1)
        raise Exception()

    users = []
    user_mapping = {}
    usernames = set()

    for user in reader.read_users():
        if ' ' in user.display_name:
            given_name, family_name = user.display_name.rsplit(' ', 1)
        else:
            given_name = user.display_name
            family_name = ""
        if user.email is None:
            print("Skip", user)
            continue

        if args.keep_ids:
            existing_user = mongo.user_collection.find_one(
                {'$or': [{'email': user.email}, {'_id': user.uid}]}, {'_id': 1}
            )
        else:
            existing_user = mongo.user_collection.find_one({'email': user.email}, {'_id': 1})
        if existing_user is not None:
            print("Update", user)
            user_mapping[user.uid] = existing_user['_id']
            mongo.user_collection.update_one(
                {'_id': existing_user['_id']}, {'$addToSet': {'groups': {'$each': user.groups}}}
            )
            user_history_collection.insert_one(DbUserHistory(
                id=str(uuid4()),
                user_id=existing_user['_id'],
                timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
                author_id='batch',
                changes=[DbChange(property='groups', value=f'Added {", ".join(user.groups)}')],
            ).dict(by_alias=True, exclude_none=True))
            continue

        preferred_username = base_username = normalize_username(user.display_name)
        username_counter = 2
        while (
                mongo.user_collection.count_documents({'preferred_username': preferred_username}, limit=1) != 0 or
                preferred_username in usernames
        ):
            preferred_username = base_username + str(username_counter)
            username_counter += 1
        usernames.add(preferred_username)

        if args.keep_ids:
            new_id = user.uid
        else:
            new_id = generate_token(48)
        user_mapping[user.uid] = new_id

        users.append(
            DbUser(
                id=new_id,
                email=user.email,
                active=True,
                email_verified=user.email_verified,
                notes=f"Imported '{user.uid}' from OC",
                groups=user.groups + ['users'],
                locale=user.language,
                zoneinfo=user.timezone,
                password=user.password,
                phone_number=user.phone,
                phone_number_verified=False,
                updated_at=int(time.time()),
                preferred_username=preferred_username,
                given_name=given_name,
                family_name=family_name,
                # This token is not usable, but it enforces that the user reviews the user credentials before logging in
                registration_token='imported',
            ).document()
        )
        print("Create", users[-1])

    groups = []
    for group in reader.read_groups():
        members = [user_mapping[member] for member in group.members]
        gid = group.gid.lower()
        if mongo.user_group_collection.count_documents({'_id': gid}, limit=1) != 0:
            mongo.user_group_collection.update_one(
                {'_id': gid},
                {'$addToSet': {'members': {'$each': members}}}
            )
            print(f"Update group {gid}")
        else:
            groups.append(DbUserGroup(
                id=gid,
                group_name=group.display_name,
                notes="Imported from OC",
                group_type="team",
                visible=True,
                member_groups=[],
                members=members,
            ).document())
            print("Create group", groups[-1])

    if users:
        mongo.user_collection.insert_many(users)
    if groups:
        mongo.user_group_collection.insert_many(groups)
    mongo.user_group_collection.update_one(
        {'_id': 'users'},
        {'$addToSet': {'members': {'$each': list(user_mapping.values())}}}
    )
