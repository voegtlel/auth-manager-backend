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


def none_str(x):
    if x is None:
        return None
    if isinstance(x, bytes):
        return x.decode()
    return str(x)


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
            password = none_str(password)
            if password and len(password) > 2 and password[1] == '|':
                password = password[2:]
            groups_cursor.execute(groups_query, (uid,))
            groups = [none_str(gid) for gid, in groups_cursor]
            profile = UserData(
                uid=uid,
                display_name=none_str(displayname or account.get('displayname', {}).get('value')),
                password=password,
                address=none_str(account.get('address', {}).get('value')),
                email=none_str(account.get('email', {}).get('value')),
                email_verified=none_str(account.get('email', {}).get('verified', "0")) != "0",
                phone=none_str(account.get('phone', {}).get('value')),
                groups=groups,
            )
            for appid, configkey, configvalue in preferences_cursor:
                if (appid, configkey) == ('core', 'timezone'):
                    profile.timezone = none_str(configvalue)
                elif (appid, configkey) == ('core', 'lang'):
                    profile.language = none_str(configvalue)
                elif (appid, configkey) == ('settings', 'email') and configvalue is not None:
                    profile.email = none_str(configvalue)
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
            members = [none_str(uid) for uid, in member_cursor]
            yield GroupData(gid=none_str(gid), display_name=none_str(displayname), members=members)
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

    parser.add_argument(
        '--overwrite',
        action='store_true',
        help="... or use environment variable UPDATE_OVERWRITE='1'. If provided, and --keep-ids, then overwrite user.",
        default=os.environ.get('UPDATE_OVERWRITE', '0') == '1',
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

    remove_teams = {}

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
                {'$or': [{'email': user.email}, {'preferred_username': user.uid}]}, {'_id': 1, 'groups': 1, 'name': 1}
            )
            print(f"Searching email={user.email!r} and preferred_username={user.uid!r} -> {existing_user}")
        else:
            existing_user = mongo.user_collection.find_one({'email': user.email}, {'_id': 1, 'groups': 1, 'name': 1})
            print(f"Searching email={user.email!r} -> {existing_user}")
        if existing_user is not None:
            existing_user_id = existing_user['_id']
            if args.overwrite:
                print("Overwrite groups and password of", user)
                user_mapping[user.uid] = existing_user_id
                for group in set(existing_user['groups']) - set(user.groups):
                    remove_team = remove_teams.get(group)
                    if remove_team is None:
                        remove_teams[group] = [existing_user_id]
                    else:
                        remove_team.append(existing_user_id)
                mongo.user_collection.update_one(
                    {'_id': existing_user_id}, {'$set': {
                        'groups': list(set(user.groups)), 'password': user.password
                    }}
                )
                mongo.user_history_collection.insert_one(DbUserHistory(
                    id=str(uuid4()),
                    user_id=existing_user_id,
                    timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
                    author_id='batch',
                    changes=[DbChange(property='groups', value=f'Set {", ".join(user.groups)}')],
                ).dict(by_alias=True, exclude_none=True))
                mongo.user_history_collection.insert_one(DbUserHistory(
                    id=str(uuid4()),
                    user_id=existing_user_id,
                    timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
                    author_id='batch',
                    changes=[DbChange(property='password', value='Set')],
                ).dict(by_alias=True, exclude_none=True))
            else:
                print("Update groups of", user)
                user_mapping[user.uid] = existing_user_id
                new_groups = set(user.groups) - set(existing_user['groups'])
                if len(new_groups) > 0:
                    mongo.user_collection.update_one(
                        {'_id': existing_user_id}, {'$addToSet': {'groups': {'$each': new_groups}}}
                    )
                    mongo.user_history_collection.insert_one(DbUserHistory(
                        id=str(uuid4()),
                        user_id=existing_user_id,
                        timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
                        author_id='batch',
                        changes=[DbChange(property='groups', value=f'Added {", ".join(user.groups)}')],
                    ).dict(by_alias=True, exclude_none=True))
            continue

        new_id = generate_token(48)
        if args.keep_ids:
            preferred_username = user.uid
        else:
            preferred_username = base_username = normalize_username(user.display_name)
            username_counter = 2
            while (
                    mongo.user_collection.count_documents({'preferred_username': preferred_username}, limit=1) != 0 or
                    preferred_username in usernames
            ):
                preferred_username = base_username + str(username_counter)
                username_counter += 1
        usernames.add(preferred_username)
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
        gid = group.gid
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
    for group_id, remove_users in remove_teams.items():
        mongo.user_group_collection.update_one(
            {'_id': group_id},
            {'$pull': {'members': {'$in': remove_users}}}
        )
    if users:
        mongo.user_collection.insert_many(users)
    if groups:
        mongo.user_group_collection.insert_many(groups)
    mongo.user_group_collection.update_one(
        {'_id': 'users'},
        {'$addToSet': {'members': {'$each': list(user_mapping.values())}}}
    )
    mongo.client_user_cache_collection.delete_many({'user_id': {'$in': list(user_mapping.values())}})
