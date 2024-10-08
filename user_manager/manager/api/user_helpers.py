import re
from base64 import b64encode, b64decode
from datetime import datetime
from typing import Dict, Any, Optional, Sequence, List
from uuid import uuid4

import time
from authlib.common.security import generate_token
from fastapi import HTTPException
from pydantic import BaseModel
from pydantic.datetime_parse import parse_datetime, parse_date
from pyisemail import is_email
from unidecode import unidecode

from user_manager.common.config import config
from user_manager.common.models import DbUser, DbUserPasswordAccessToken, UserPropertyType, DbUserHistory, DbChange, \
    DbManagerSchema, DbUserProperty
from user_manager.common.mongo import async_user_collection, \
    async_client_user_cache_collection, async_authorization_code_collection, async_session_collection, \
    async_token_collection, async_user_group_collection, user_collection, async_user_history_collection, \
    async_read_schema
from user_manager.common.password_helper import verify_and_update, create_password, PasswordLeakedException
from user_manager.manager.helper import get_regex, DotDict
from user_manager.manager.mailer import mailer


class ValidateAccessToken(BaseModel):
    id: Optional[str] = None
    description: str
    token: Optional[str] = None


replace_dot_re = re.compile(r'\b[\s]+\b')
remove_re = re.compile(r'[^a-z0-9.-]')


def normalize_username(display_name: str) -> str:
    if config.oauth2.use_german_username_translation:
        display_name = display_name.replace('ä', 'ae').replace('ö', 'oe').replace('ü', 'ue')
    username = unidecode(display_name).lower()
    username = replace_dot_re.sub('.', username)
    username = remove_re.sub('', username)
    return username


async def async_send_mail_register(
        user_data: DotDict,
        schema: DbManagerSchema,
        token_valid_until: int,
        locale: str = None,
        tz: datetime.tzinfo = None,
        author_id: str = None,
        history_entry: DbUserHistory = None,
):
    if tz is None:
        tz = schema.get_tz(user_data.get('zoneinfo'))
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
    if history_entry is None:
        await async_user_history_collection.insert_one(
            DbUserHistory(
                id=str(uuid4()),
                user_id=user_data['_id'] if author_id is None else author_id,
                timestamp=datetime.utcnow(),
                author_id=user_data['_id'],
                changes=[
                    DbChange(property='email', value="Sent Registration E-Mail"),
                ],
            ).dict(by_alias=True, exclude_none=True)
        )
    else:
        history_entry.changes.append(DbChange(property='email', value="Sent Registration E-Mail"))
    return f"{config.manager.frontend_base_url}/register/{user_data['registration_token']}"


async def async_send_mail_verify(
        locale: Optional[str],
        mail: str,
        user_data: DotDict,
        token_valid_until: int,
        tz: datetime.tzinfo,
        author_id: str = None,
        history_entry: DbUserHistory = None,
) -> str:
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
    if history_entry is None:
        await async_user_history_collection.insert_one(
            DbUserHistory(
                id=str(uuid4()),
                user_id=user_data['_id'] if author_id is None else author_id,
                timestamp=datetime.utcnow(),
                author_id=user_data['_id'],
                changes=[
                    DbChange(property='email', value="Sent E-Mail Verification E-Mail"),
                ],
            ).dict(by_alias=True, exclude_none=True)
        )
    else:
        history_entry.changes.append(
            DbChange(property='email', value="Sent E-Mail Verification E-Mail")
        )
    return f"{config.manager.frontend_base_url}/verify-email/{user_data['email_verification_token']}"


async def async_send_mail_reset_password(
        user_data: DotDict,
        schema: DbManagerSchema,
        token_valid_until: int,
        tz: datetime.tzinfo = None,
        author_id: str = None,
) -> str:
    if tz is None:
        tz = schema.get_tz(user_data.get('zoneinfo'))
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
    await async_user_history_collection.insert_one(
        DbUserHistory(
            id=str(uuid4()),
            user_id=user_data['_id'] if author_id is None else author_id,
            timestamp=datetime.utcnow(),
            author_id=user_data['_id'],
            changes=[
                DbChange(property='email', value="Sent Reset Password E-Mail"),
            ],
        ).dict(by_alias=True, exclude_none=True)
    )
    return f"{config.manager.frontend_base_url}/reset-password/{user_data['password_reset_token']}"


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


async def update_resend_registration(
        user_data: DotDict,
        schema: DbManagerSchema,
        author_id: str,
) -> str:
    token_valid_until = int(time.time() + config.manager.token_valid.registration)
    user_data['registration_token'] = create_token(user_data['_id'], token_valid_until)
    await async_user_collection.update_one({'_id': user_data['_id']}, {
        '$set': {
            'registration_token': user_data['registration_token'],
            'updated_at': int(time.time()),
        }
    })
    await async_client_user_cache_collection.delete_many({'user_id': user_data['_id']})
    return await async_send_mail_register(user_data, schema, token_valid_until, author_id=author_id)


def validate_property_write(schema: DbManagerSchema, key: str, is_self: bool, is_admin: bool):
    prop = schema.properties_by_key.get(key)
    if prop is None:
        raise HTTPException(400, f"{repr(key)}={repr(prop)} is not a valid property")
    elif not prop.can_edit.has_access(is_self, is_admin):
        raise HTTPException(400, f"Cannot modify {repr(key)}")


def make_username(name: str) -> str:
    username = base_username = normalize_username(name)
    username_counter = 2
    while user_collection.count_documents({'preferred_username': username}, limit=1) != 0:
        username = base_username + str(username_counter)
        username_counter += 1
    return username


async def _update_groups(
        user_data: DotDict,
        schema: DbManagerSchema,
        update_data: Dict[str, Any],
        history_entry: DbUserHistory,
        property_key: str,
        is_self: bool,
        is_admin: bool,
        existence_check_property: Optional[str],
        groups_add_property: str,
        groups_pull_properties: Sequence[str],
        members_pull_properties: Sequence[str] = (),
) -> bool:
    if not isinstance(update_data[property_key], list) or \
            not all(isinstance(group, str) for group in update_data[property_key]):
        raise HTTPException(400, f"{repr(property_key)} must be a string")
    validate_property_write(schema, property_key, is_self, is_admin)

    reset_user_cache = False

    new_groups = update_data[property_key]
    new_groups_set = set(new_groups)
    if existence_check_property is None:
        if await async_user_group_collection.count_documents({'_id': {'$in': new_groups}}) != len(new_groups):
            raise HTTPException(400, "At least one group does not exist")
    else:
        if not new_groups_set.issubset(user_data[existence_check_property]):
            raise HTTPException(400, f"{property_key} contains invalid group")
    added_groups = list(new_groups_set.difference(user_data[property_key]))
    removed_groups = list(set(user_data[property_key]).difference(new_groups))
    user_data[property_key] = new_groups
    if added_groups:
        await async_user_group_collection.update_many(
            {'_id': {'$in': added_groups}},
            {'$addToSet': {groups_add_property: user_data['_id']}},
        )
        history_entry.changes.append(DbChange(property=groups_add_property, value=f"Added {', '.join(added_groups)}"))
        reset_user_cache = True
    if removed_groups:
        await async_user_group_collection.update_many(
            {'_id': {'$in': removed_groups}},
            {'$pull': {
                prop: user_data['_id']
                for prop in groups_pull_properties
            }},
        )
        history_entry.changes.extend(
            DbChange(property=prop, value=f"Removed {', '.join(removed_groups)}")
            for prop in groups_pull_properties
        )
        for member_property_attr in members_pull_properties:
            member_property: List[str] = user_data.get(member_property_attr, [])
            for group in removed_groups:
                try:
                    member_property.remove(group)
                except ValueError:
                    pass
        reset_user_cache = True
    del update_data[property_key]
    return reset_user_cache


def apply_property_template(user_data: DotDict, prop: DbUserProperty):
    assert "'''" not in prop.template, f"Invalid ''' in template: {prop.template}"
    user_data[prop.key] = eval(
        f"f'''{prop.template}'''",
        {'make_username': make_username, 'config': config},
        user_data,
    )


async def update_user(
        user_data: DotDict,
        update_data: Dict[str, Any],
        author_user_id: str,
        is_new: bool = False,
        is_registering: bool = False,
        is_admin: bool = False,
        is_self: bool = False,
        no_registration: bool = False,
        schema: DbManagerSchema = None,
) -> Optional[str]:
    if 'sub' in update_data or 'id' in update_data or '_id' in update_data or 'picture' in update_data:
        raise HTTPException(400, f"Cannot modify 'sub', 'id', '_id' or 'picture'")
    was_active = user_data.get('active', False)
    reset_user_cache = False

    if schema is None:
        schema = await async_read_schema()

    if is_new:
        assert '_id' not in user_data
        user_data['_id'] = generate_token(48)
    history_entry: DbUserHistory = DbUserHistory(
        id=str(uuid4()),
        user_id=user_data['_id'],
        timestamp=datetime.utcnow(),
        author_id=author_user_id,
        changes=[],
    )

    if 'password' in update_data:
        if not isinstance(update_data['password'], str):
            raise HTTPException(400, "'password' must be a string")
        validate_property_write(schema, 'password', is_self, is_admin)
        if is_self and not is_registering and user_data.get('password') is not None:
            if 'old_password' not in update_data:
                raise HTTPException(400, f"Need {repr('old_password')} for setting password")
            if not isinstance(update_data['old_password'], str):
                raise HTTPException(400, f"{repr('old_password')} is not a string")
            is_valid, _ = verify_and_update(update_data['old_password'], user_data['password'])
            if not is_valid:
                raise HTTPException(401, "Old password does not match")
            del update_data['old_password']
        try:
            user_data['password'] = create_password(update_data['password'])
            del update_data['password']
            history_entry.changes.append(DbChange(property='password', value="Set"))
        except PasswordLeakedException:
            raise HTTPException(400, "Password is leaked and cannot be used. See https://haveibeenpwned.com/")

    async def send_mail():
        pass

    if is_registering and update_data.get('email', user_data['email']) == user_data['email']:
        user_data['email_verified'] = True
        if 'email' in update_data:
            del update_data['email']
    elif 'email' in update_data:
        new_mail = update_data['email']
        if not isinstance(new_mail, str):
            raise HTTPException(400, "'email' must be a string")
        validate_property_write(schema, 'email', is_self, is_admin)
        if not is_email(new_mail, check_dns=True):
            raise HTTPException(400, "E-Mail address not accepted")

        if new_mail != user_data.get('email') and \
                await async_user_collection.count_documents({'email': new_mail}, limit=1) != 0:
            raise HTTPException(400, "E-Mail address already in use, please use existing account")
        locale = update_data.get('locale', user_data.get('locale', schema.properties_by_key['locale'].default))
        if locale is None:
            locale = 'en_us'
        tz = schema.get_tz(update_data.get('zoneinfo', user_data.get('zoneinfo')))
        del update_data['email']
        history_entry.changes.append(DbChange(property='email', value=new_mail))
        if is_new and not no_registration:
            user_data['email'] = new_mail
            user_data['email_verified'] = False
            token_valid_until = int(time.time() + config.manager.token_valid.registration)
            user_data['registration_token'] = create_token(user_data['_id'], token_valid_until)

            async def send_mail():
                return await async_send_mail_register(
                    user_data,
                    schema,
                    token_valid_until,
                    locale,
                    tz,
                    author_id=author_user_id,
                    history_entry=history_entry,
                )
        else:
            token_valid_until = int(time.time() + config.manager.token_valid.email_set)
            user_data['email_verification_token'] = create_token(new_mail, token_valid_until)
            if is_registering:
                user_data['email'] = new_mail
                user_data['email_verified'] = False

            async def send_mail():
                return await async_send_mail_verify(
                    locale,
                    new_mail,
                    user_data,
                    token_valid_until,
                    tz,
                    author_id=author_user_id,
                    history_entry=history_entry
                )

    if 'access_tokens' in update_data:
        if not isinstance(update_data['access_tokens'], list):
            raise HTTPException(400, "'access_tokens' must be a list")
        try:
            access_tokens = [ValidateAccessToken.validate(val) for val in update_data['access_tokens']]
        except ValueError as err:
            raise HTTPException(400, str(err))
        validate_property_write(schema, 'access_tokens', is_self, is_admin)
        existing_access_tokens = [
            DbUserPasswordAccessToken.validate_document(access_token)
            for access_token in user_data.get('access_tokens', [])
        ]
        existing_access_tokens_by_id = {
            existing_access_token.id: existing_access_token
            for existing_access_token in existing_access_tokens
        }
        has_change = False
        new_access_tokens = []
        for access_token in access_tokens:
            if access_token.id is not None:
                store_token = existing_access_tokens_by_id.pop(access_token.id, None)
                if store_token is None:
                    raise HTTPException(400, f"Invalid token ID {access_token.id}")
                if store_token.description != access_token.description:
                    has_change = True
                    history_entry.changes.append(DbChange(
                        property='access_tokens',
                        value=f"Rename {store_token.description} -> {access_token.description}",
                    ))
                    store_token.description = access_token.description
                if access_token.token is not None:
                    has_change = True
                    history_entry.changes.append(DbChange(
                        property='access_tokens', value=f"Regenerate {store_token.description}"
                    ))
                    store_token.token = access_token.token
            else:
                has_change = True
                store_token = DbUserPasswordAccessToken(
                    id=generate_token(24),
                    description=access_token.description,
                    token=access_token.token,
                )
                history_entry.changes.append(DbChange(
                    property='access_tokens', value=f"Added {store_token.description}"
                ))
            new_access_tokens.append(store_token)
        history_entry.changes.extend(DbChange(
            property='access_tokens', value=f"Deleted {deleted_token.description}"
        ) for deleted_token in existing_access_tokens_by_id.values())
        del update_data['access_tokens']
        user_data['access_tokens'] = [access_token.dict() for access_token in new_access_tokens]
        if has_change:
            history_entry.changes.append(DbChange(property='access_tokens', value="Updated"))

    if 'groups' in update_data:
        if await _update_groups(
            user_data,
            schema,
            update_data,
            history_entry,
            property_key='groups',
            is_self=is_self,
            is_admin=is_admin,
            existence_check_property=None,
            groups_add_property='members',
            groups_pull_properties=(
                'members', 'email_allowed_forward_members', 'email_forward_members', 'email_postbox_access_members',
            ),
            members_pull_properties=(
                'email_allowed_forward_members', 'email_forward_members', 'email_postbox_access_members',
            ),
        ):
            reset_user_cache = True

    if 'email_allowed_forward_groups' in update_data:
        await _update_groups(
            user_data,
            schema,
            update_data,
            history_entry,
            property_key='email_allowed_forward_groups',
            is_self=is_self,
            is_admin=is_admin,
            existence_check_property='groups',
            groups_add_property='email_allowed_forward_members',
            groups_pull_properties=('email_allowed_forward_members', 'email_forward_members'),
            members_pull_properties=('email_forward_members',)
        )

    if 'email_forward_groups' in update_data:
        await _update_groups(
            user_data,
            schema,
            update_data,
            history_entry,
            property_key='email_forward_groups',
            is_self=is_self,
            is_admin=is_admin,
            existence_check_property='email_allowed_forward_groups',
            groups_add_property='email_forward_members',
            groups_pull_properties=('email_forward_members',),
        )

    if 'email_postbox_access_groups' in update_data:
        await _update_groups(
            user_data,
            schema,
            update_data,
            history_entry,
            property_key='email_postbox_access_groups',
            is_self=is_self,
            is_admin=is_admin,
            existence_check_property='groups',
            groups_add_property='email_postbox_access_members',
            groups_pull_properties=('email_postbox_access_members',),
        )

    for key, value in update_data.items():
        validate_property_write(schema, key, is_self, is_admin)
        prop = schema.properties_by_key[key]
        if prop.write_once and user_data.get(key) is not None:
            raise HTTPException(400, f"{repr(key)} can only be set once")
        if value is None and not prop.required and key in user_data:
            del user_data[key]
            history_entry.changes.append(DbChange(property=key, value="<Deleted>"))
        elif prop.type in (UserPropertyType.str, UserPropertyType.multistr, UserPropertyType.token):
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a string")
            if prop.template is not None:
                raise HTTPException(400, f"{repr(key)}={repr(value)} is generated")
            if prop.format is not None:
                regex = get_regex(prop.format)
                if not regex.fullmatch(value):
                    raise HTTPException(400, f"{repr(key)}={repr(value)} does not match pattern {repr(regex.pattern)}")
            user_data[key] = value
            history_entry.changes.append(DbChange(property=key, value=value))
        elif prop.type == UserPropertyType.int:
            if isinstance(value, float):
                if not value.is_integer():
                    raise HTTPException(400, f"{repr(key)}={repr(value)} is not an integer")
                value = int(value)
            if not isinstance(value, int):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not an integer")
            user_data[key] = value
            history_entry.changes.append(DbChange(property=key, value=value))
        elif prop.type == UserPropertyType.bool:
            if not isinstance(value, bool):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a boolean")
            user_data[key] = value
            history_entry.changes.append(DbChange(property=key, value=value))
        elif prop.type == UserPropertyType.datetime:
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a datetime string")
            try:
                parse_datetime(value)
                user_data[key] = value
                history_entry.changes.append(DbChange(property=key, value=value))
            except ValueError:
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a datetime string")
        elif prop.type == UserPropertyType.date:
            if not isinstance(value, str):
                raise HTTPException(400, f"{repr(key)}={repr(value)} is not a date string")
            try:
                parse_date(value)
                user_data[key] = value
                history_entry.changes.append(DbChange(property=key, value=value))
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
            history_entry.changes.append(DbChange(property=key, value=value))
        else:
            raise NotImplementedError(f"{key}: {repr(prop.type)}")

    # Set others to default
    if is_new or is_registering:
        for key, value in schema.properties_by_key.items():
            if value.default is not None and key not in user_data:
                user_data[key] = value.default

    # Activate the user after registration
    if is_registering:
        user_data['active'] = True
        history_entry.changes.append(DbChange(property='active', value=True))

    if is_new:
        # Validate that all required variables are present
        for key, value in schema.properties_by_key.items():
            if value.new_required and user_data.get(key) is None:
                raise HTTPException(400, f"Missing {repr(key)}")
    # Apply all templates and validate required, when not active
    if user_data.get('active', False):
        # Validate that all required variables are present
        for key, value in schema.properties_by_key.items():
            if value.required and user_data.get(key) is None:
                raise HTTPException(400, f"Missing {repr(key)}")
        # Apply templates (they should not be required)
        for key, value in schema.properties_by_key.items():
            if (
                    value.type == UserPropertyType.str and value.template is not None and
                    (not value.write_once or not user_data.get(key))
            ):
                apply_property_template(user_data, value)
    else:
        # Apply non-once templates
        for key, value in schema.properties_by_key.items():
            if (
                    value.type == UserPropertyType.str and value.template is not None and
                    not value.write_once
            ):
                apply_property_template(user_data, value)

    user_data['updated_at'] = int(time.time())

    DbUser.validate_document(user_data)

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
    return await send_mail()
