import time
from base64 import b64encode, b64decode
from datetime import datetime
from typing import Dict, Any, List

from authlib.common.security import generate_token
from fastapi import HTTPException
from pydantic.datetime_parse import parse_datetime
from pyisemail import is_email
from pytz import UTC, timezone, UnknownTimeZoneError

from user_manager.common.config import config, AccessType, UserPropertyType
from user_manager.common.models import UserGroup, User
from user_manager.common.mongo import user_group_collection, client_user_cache_collection, \
    user_collection, token_collection, session_collection, authorization_code_collection
from user_manager.common.password_helper import verify_and_update, create_password, PasswordLeakedException
from user_manager.manager.helper import get_regex
from user_manager.manager.mailer import mailer


def _create_token(data: str, valid_until: int):
    return (
            b64encode(data.encode()).decode('utf-8').replace('/', '_').replace('=', '') +
            '-' + generate_token(48) + '-' + str(valid_until)
    )


def check_token(token: str) -> str:
    """Checks the token for validity and returns the associated data"""
    token_parts = token.split('-')
    if len(token_parts) != 3:
        raise HTTPException(400, "Token invalid")
    data_b64, token, valid_until_raw = token_parts
    try:
        data_b64.replace('_', '/')
        if len(data_b64) % 4 == 2:
            data_b64 += '=='
        elif len(data_b64) % 4 == 3:
            data_b64 += '='
        data = b64decode(data_b64).decode()
        valid_until = int(valid_until_raw)
    except ValueError:
        raise HTTPException(400, "Token invalid")
    if valid_until < int(time.time()):
        raise HTTPException(400, "Token expired")
    return data


def _reset_password(
        user_data: Dict[str, Any],
):
    token_valid_until = int(time.time() + config.manager.token_valid.password_reset)
    user_data['password_reset_token'] = _create_token(user_data['_id'], token_valid_until)

    mailer.send_mail(
        user_data.get('locale', user_data.get('locale', 'en_us')),
        'password_reset',
        user_data['email'],
        {
            'password_reset_link': f"password_reset/{user_data['password_reset_token']}",
            'valid_until': datetime.fromtimestamp(token_valid_until, UTC)
        },
    )


def _resolve_groups(
        group_ids: List[str]
) -> Dict[str, List[str]]:
    return {
        group_data['_id']: [grp['_id'] for grp in group_data['sub_groups']]
        for group_data in user_group_collection.aggregate([
            {
                '$match': {'_id': {'$in': group_ids}},
            },
            {
                '$graphLookup': {
                    'from': UserGroup.__collection_name__,
                    'startWith': '$member_groups',
                    'connectFromField': 'member_groups',
                    'connectToField': '_id',
                    'as': 'sub_groups'
                }
            },
            {
                '$project': {
                    '_id': 1,
                    'sub_groups._id': 1,
                }
            }
        ])
    }


def update_user(
        user_data: Dict[str, Any],
        update_data: Dict[str, Any],
        is_new: bool = False,
        is_registering: bool = False,
        is_admin: bool = False,
        is_self: bool = False,
):
    if 'sub' in update_data or '_id' in update_data or 'picture' in update_data:
        raise HTTPException(400, f"Cannot modify 'sub', '_id' or 'picture'")
    was_active = user_data.get('active', False)

    if is_new:
        assert '_id' not in user_data
        user_data['_id'] = generate_token(48)

    if 'password' in update_data:
        if not isinstance(update_data['password'], str):
            raise HTTPException(400, f"{repr('password')} is not a string")
        if is_self and not is_registering and user_data.get('password') is not None:
            if 'old_password' not in update_data:
                raise HTTPException(400, f"Need {repr('old_password')} for setting password")
            if not isinstance(update_data['old_password'], str):
                raise HTTPException(400, f"{repr('old_password')} is not a string")
            is_valid, _ = verify_and_update(update_data['old_password'], user_data['password'])
            if not is_valid:
                raise HTTPException(401, "Old password does not match")
        try:
            user_data['password'] = create_password(update_data['password'])
            del update_data['password']
        except PasswordLeakedException:
            raise HTTPException(400, "Password is leaked and cannot be used. See https://haveibeenpwned.com/")

    if 'email' in update_data:
        if not is_email(update_data['email'], check_dns=True):
            raise HTTPException(400, "E-Mail address not accepted")
        new_mail = update_data['email']
        locale = update_data.get('locale', user_data.get('locale', config.oauth2.user.properties['locale'].default))
        if locale is None:
            locale = 'en_us'
        zoneinfo = update_data.get('zoneinfo', user_data.get('zoneinfo', config.oauth2.user.properties['zoneinfo'].default))
        if zoneinfo is None:
            tz = UTC
        else:
            try:
                tz = timezone(zoneinfo)
            except UnknownTimeZoneError:
                tz = UTC
        del update_data['email']
        if is_new:
            user_data['email'] = new_mail
            user_data['email_verified'] = False
            token_valid_until = int(time.time() + config.manager.token_valid.registration)
            user_data['registration_token'] = _create_token(user_data['_id'], token_valid_until)

            def send_mail():
                mailer.send_mail(
                    locale,
                    'register',
                    new_mail,
                    {
                        'registration_link': f"register/{user_data['registration_token']}",
                        'valid_until': datetime.fromtimestamp(token_valid_until, tz),
                        'user': user_data,
                    },
                )
        elif is_registering and update_data.get('email') == user_data['email']:
            user_data['email_verified'] = True

            def send_mail():
                pass
        elif not is_admin:
            token_valid_until = int(time.time() + config.manager.token_valid.email_set)
            user_data['email_verification_token'] = _create_token(new_mail, token_valid_until)
            if is_registering:
                user_data['email'] = new_mail
                user_data['email_verified'] = False

            def send_mail():
                mailer.send_mail(
                    locale,
                    'verify_mail',
                    new_mail,
                    {
                        'verify_link': f"verify-email/{user_data['email_verification_token']}",
                        'valid_until': datetime.fromtimestamp(token_valid_until, tz),
                        'user': user_data,
                    },
                )
        else:
            user_data['email'] = new_mail
            user_data['email_verified'] = False

            def send_mail():
                pass
    else:
        def send_mail():
            pass

    if 'groups' in update_data:
        new_groups = update_data['groups']
        if user_group_collection.count_documents({'_id': {'$in': new_groups}}) != len(new_groups):
            raise HTTPException(404, "At least one group does not exist")
        added_groups = list(set(new_groups).difference(user_data['groups']))
        removed_groups = list(set(user_data['groups']).difference(new_groups))
        user_data['groups'] = new_groups
        if added_groups:
            user_group_collection.update_many(
                {'_id': {'$in': added_groups}},
                {'$addToSet': {'members': user_data['_id']}},
            )
        if removed_groups:
            user_group_collection.update_many(
                {'_id': {'$in': removed_groups}},
                {'$pull': {'members': user_data['_id']}},
            )
        del update_data['groups']

    for key, value in update_data.items():
        prop = config.oauth2.user.properties.get(key)
        if prop is None:
            raise HTTPException(400, f"{repr(key)}={repr(value)} is not a valid property")
        elif prop.can_edit is AccessType.nobody:
            raise HTTPException(400, f"Cannot modify {repr(key)}")
        elif prop.can_edit is AccessType.admin and not is_admin:
            raise HTTPException(401, f"Cannot modify {repr(key)}")
        elif prop.can_edit is AccessType.self and not (is_self or is_admin):
            raise HTTPException(401, f"Cannot modify {repr(key)}")
        if value is None and not prop.required:
            del user_data[key]
        if prop.type in (UserPropertyType.str, UserPropertyType.multistr):
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a string")
            if prop.template is not None:
                raise HTTPException(400, f"{repr(key)}={repr(value)} is generated")
            if prop.format is not None:
                regex = get_regex(prop.format)
                if not regex.fullmatch(value):
                    raise HTTPException(400, f"{repr(key)}={repr(value)} does not match pattern {repr(regex.pattern)}")
            user_data[key] = value
        elif prop.type == UserPropertyType.bool:
            if not isinstance(value, bool):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a boolean")
            user_data[key] = value
        elif prop.type == UserPropertyType.datetime:
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a datetime string")
            try:
                user_data[key] = parse_datetime(value)
            except ValueError:
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a datetime string")
        elif prop.type == UserPropertyType.enum:
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a string")
            assert prop.values is not None
            values = [enum_value.value for enum_value in prop.values]
            if value not in values:
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a valid enum value")
            user_data[key] = value
        else:
            raise NotImplementedError()

    # Set others to default
    if is_new:
        for key, value in config.oauth2.user.properties.items():
            if value.default is not None and key not in user_data:
                user_data[key] = value.default

    # Activate the user after registration
    if is_registering:
        user_data['active'] = True

    # Apply all templates and validate required
    if not is_new:
        # Validate that all required variables are present
        for key, value in config.oauth2.user.properties.items():
            if value.required and user_data.get(key) is None:
                raise HTTPException(400, f"Missing {repr(key)}")
        # Apply templates (they should not be required)
        for key, value in config.oauth2.user.properties.items():
            if value.type == UserPropertyType.str and value.template is not None:
                assert "'''" not in value.template, f"Invalid ''' in template: {value.template}"
                user_data[key] = eval(f"f'''{value.template}'''", {}, user_data)

    user_data['updated_at'] = int(time.time())

    User.validate(user_data)

    if is_new:
        user_collection.insert_one(user_data)
    else:
        user_collection.replace_one({'_id': user_data['_id']}, user_data)
    if user_data.get('active', False):
        client_user_cache_collection.update_many(
            {'user_id': user_data['_id']},
            {'$set': {'last_modified': user_data['updated_at']}},
        )
    elif was_active:
        client_user_cache_collection.delete_many({'user_id': user_data['_id']})
        token_collection.delete_many({'user_id': user_data['_id']})
        session_collection.delete_many({'user_id': user_data['_id']})
        authorization_code_collection.delete_many({'user_id': user_data['_id']})
    # Last: Send the email if there is one
    send_mail()
