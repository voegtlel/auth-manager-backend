import time
from base64 import b64encode, b64decode
from datetime import datetime
from typing import Dict, Any, Optional

from authlib.common.security import generate_token
from fastapi import HTTPException
from pydantic.datetime_parse import parse_datetime, parse_date
from pyisemail import is_email
from pytz import UTC, timezone, UnknownTimeZoneError

from user_manager.common.config import config, AccessType, UserPropertyType
from user_manager.common.models import User
from user_manager.common.mongo import async_user_collection, \
    async_client_user_cache_collection, async_authorization_code_collection, async_session_collection, \
    async_token_collection, async_user_group_collection
from user_manager.common.password_helper import verify_and_update, create_password, PasswordLeakedException
from user_manager.manager.helper import get_regex, DotDict
from user_manager.manager.mailer import mailer


def _get_tz(zoneinfo: str = None) -> datetime.tzinfo:
    if zoneinfo is None:
        zoneinfo = config.oauth2.user.properties['zoneinfo'].default
    try:
        return timezone(zoneinfo)
    except UnknownTimeZoneError:
        return UTC


async def async_send_mail_register(
        user_data: DotDict, token_valid_until: int, locale: str = None, tz: datetime.tzinfo = None
):
    if tz is None:
        tz = _get_tz(user_data.get('zoneinfo'))
    if locale is None:
        locale = user_data.get('locale', 'en_us'),
    await mailer.async_send_mail(
        locale,
        'register',
        user_data['email'],
        {
            'registration_link': f"register/{user_data['registration_token']}",
            'valid_until': datetime.fromtimestamp(token_valid_until, tz),
            'user': user_data,
        },
    )


async def async_send_mail_verify(
        locale: Optional[str], mail: str, user_data: DotDict, token_valid_until: int, tz: datetime.tzinfo
):
    if locale is None:
        locale = user_data.get('locale', 'en_us'),
    await mailer.async_send_mail(
        locale,
        'verify_mail',
        mail,
        {
            'verify_link': f"verify-email/{user_data['email_verification_token']}",
            'valid_until': datetime.fromtimestamp(token_valid_until, tz),
            'user': user_data,
        },
    )


async def async_send_mail_reset_password(user_data: DotDict, token_valid_until: int, tz: datetime.tzinfo = None):
    if tz is None:
        tz = _get_tz(user_data.get('zoneinfo'))
    await mailer.async_send_mail(
        user_data.get('locale', 'en_us'),
        'password_reset',
        user_data['email'],
        {
            'password_reset_link': f"reset-password/{user_data['password_reset_token']}",
            'valid_until': datetime.fromtimestamp(token_valid_until, tz),
            'user': user_data,
        },
    )


def create_token(data: str, valid_until: int):
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


async def update_resend_registration(user_data: DotDict):
    token_valid_until = int(time.time() + config.manager.token_valid.registration)
    user_data['registration_token'] = create_token(user_data['_id'], token_valid_until)
    await async_user_collection.update_one({'_id': user_data['_id']}, {
        '$set': {
            'registration_token': user_data['registration_token'],
            'updated_at': int(time.time()),
        }
    })
    await async_client_user_cache_collection.delete_many({'user_id': user_data['_id']})
    await async_send_mail_register(user_data, token_valid_until)


def _validate_property_write(key: str, is_self: bool, is_admin: bool):
    prop = config.oauth2.user.properties.get(key)
    if prop is None:
        raise HTTPException(400, f"{repr(key)}={repr(prop)} is not a valid property")
    elif prop.can_edit is AccessType.nobody:
        raise HTTPException(400, f"Cannot modify {repr(key)}")
    elif prop.can_edit is AccessType.admin and not is_admin:
        raise HTTPException(401, f"Cannot modify {repr(key)}")
    elif prop.can_edit is AccessType.self and not (is_self or is_admin):
        raise HTTPException(401, f"Cannot modify {repr(key)}")


async def update_user(
        user_data: DotDict,
        update_data: Dict[str, Any],
        is_new: bool = False,
        is_registering: bool = False,
        is_admin: bool = False,
        is_self: bool = False,
):
    if 'sub' in update_data or '_id' in update_data or 'picture' in update_data:
        raise HTTPException(400, f"Cannot modify 'sub', '_id' or 'picture'")
    was_active = user_data.get('active', False)
    reset_user_cache = False

    if is_new:
        assert '_id' not in user_data
        user_data['_id'] = generate_token(48)

    if 'password' in update_data:
        _validate_property_write('password', is_self, is_admin)
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
        _validate_property_write('email', is_self, is_admin)
        if not is_email(update_data['email'], check_dns=True):
            raise HTTPException(400, "E-Mail address not accepted")
        if await async_user_collection.count_documents({'email': update_data['email']}, limit=1) != 0:
            raise HTTPException(400, "E-Mail address already in use, please use existing account")
        new_mail = update_data['email']
        locale = update_data.get('locale', user_data.get('locale', config.oauth2.user.properties['locale'].default))
        if locale is None:
            locale = 'en_us'
        tz = _get_tz(update_data.get('zoneinfo', user_data.get('zoneinfo')))
        del update_data['email']
        if is_new:
            user_data['email'] = new_mail
            user_data['email_verified'] = False
            token_valid_until = int(time.time() + config.manager.token_valid.registration)
            user_data['registration_token'] = create_token(user_data['_id'], token_valid_until)

            async def send_mail():
                await async_send_mail_register(user_data, token_valid_until, locale, tz)
        elif is_registering and update_data.get('email') == user_data['email']:
            user_data['email_verified'] = True

            async def send_mail():
                pass
        elif not is_admin:
            token_valid_until = int(time.time() + config.manager.token_valid.email_set)
            user_data['email_verification_token'] = create_token(new_mail, token_valid_until)
            if is_registering:
                user_data['email'] = new_mail
                user_data['email_verified'] = False

            async def send_mail():
                await async_send_mail_verify(locale, new_mail, user_data, token_valid_until, tz)
        else:
            user_data['email'] = new_mail
            user_data['email_verified'] = False

            async def send_mail():
                pass
    else:
        async def send_mail():
            pass

    if 'groups' in update_data:
        _validate_property_write('groups', is_self, is_admin)

        new_groups = update_data['groups']
        if await async_user_group_collection.count_documents({'_id': {'$in': new_groups}}) != len(new_groups):
            raise HTTPException(404, "At least one group does not exist")
        added_groups = list(set(new_groups).difference(user_data['groups']))
        removed_groups = list(set(user_data['groups']).difference(new_groups))
        user_data['groups'] = new_groups
        if added_groups:
            await async_user_group_collection.update_many(
                {'_id': {'$in': added_groups}},
                {'$addToSet': {'members': user_data['_id']}},
            )
            reset_user_cache = True
        if removed_groups:
            await async_user_group_collection.update_many(
                {'_id': {'$in': removed_groups}},
                {'$pull': {'members': user_data['_id']}},
            )
            reset_user_cache = True
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
                parse_datetime(value)
                user_data[key] = value
            except ValueError:
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a datetime string")
        elif prop.type == UserPropertyType.date:
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a date string")
            try:
                parse_date(value)
                user_data[key] = value
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

    # Apply all templates and validate required, when not active
    if user_data.get('active', False):
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
        await async_user_collection.insert_one(user_data)
    else:
        await async_user_collection.replace_one({'_id': user_data['_id']}, user_data)
    if user_data.get('active', False):
        if reset_user_cache:
            await async_client_user_cache_collection.delete_many({'user_id': user_data['_id']})
        else:
            await async_client_user_cache_collection.update_many(
                {'user_id': user_data['_id']},
                {'$set': {'last_modified': user_data['updated_at']}},
            )
    elif was_active:
        await async_client_user_cache_collection.delete_many({'user_id': user_data['_id']})
        await async_token_collection.delete_many({'user_id': user_data['_id']})
        await async_session_collection.delete_many({'user_id': user_data['_id']})
        await async_authorization_code_collection.delete_many({'user_id': user_data['_id']})
    elif reset_user_cache:
        await async_client_user_cache_collection.delete_many({'user_id': user_data['_id']})
    # Last: Send the email if there is one
    await send_mail()
