import json
import os

from user_manager.common.models import DbManagerSchema, DbEnumValue, DbUserProperty, DbUserScope, DbUserScopeProperty, \
    DbGroupType, UserPropertyType, UserGroupPropertyType, AccessType, DbUserView, DbUserViewGroup

with open(os.path.join(os.path.dirname(__file__), 'country_names.json'), 'r', encoding='utf-8') as rf:
    countries = json.load(rf)

default_schema = DbManagerSchema(
    user_properties=[
        DbUserProperty(
            key="id",
            title="User ID",
            type=UserPropertyType.str,
            protected=True,
        ),
        DbUserProperty(
            key="active",
            title="Login Enabled",
            type=UserPropertyType.bool,
            default=False,
            can_edit=AccessType.admin,
            can_read=AccessType.self,
            visible=AccessType.admin,
            protected=True,
        ),
        DbUserProperty(
            key="name",
            title="Display Name",
            type=UserPropertyType.str,
            visible=AccessType.admin,
            template="{given_name} {family_name}",
        ),
        DbUserProperty(
            key="preferred_username",
            title="Preferred Username (ID)",
            type=UserPropertyType.str,
            can_edit=AccessType.nobody,
            can_read=AccessType.admin,
            visible=AccessType.admin,
            write_once=True,
            protected=True,
            template="{make_username(name)}",
        ),
        DbUserProperty(
            key="email",
            title="E-Mail",
            type=UserPropertyType.email,
            required=True,
            format=r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
            format_help="ab@c.de",
            can_edit=AccessType.self,
            protected=True,
        ),
        DbUserProperty(
            key="email_verified",
            title="E-Mail Verified",
            type=UserPropertyType.bool,
            can_edit=AccessType.admin,
            visible=AccessType.nobody,
            protected=True,
        ),
        DbUserProperty(
            key="has_email_alias",
            title="Enable E-Mail Alias",
            type=UserPropertyType.bool,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            visible=AccessType.nobody,
            default=False,
        ),
        DbUserProperty(
            key="forward_emails",
            title="Forward E-Mails to registered E-Mail",
            type=UserPropertyType.bool,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            visible=AccessType.nobody,
            default=True,
            protected=True,
        ),
        DbUserProperty(
            key="email_alias",
            title="E-Mail Alias",
            type=UserPropertyType.str,
            can_read=AccessType.everybody,
            can_edit=AccessType.nobody,
            visible=AccessType.nobody,
            write_once=True,
            template="{preferred_username.lower()}@{config.oauth2.mail_domain.lower()}",
            protected=True,
        ),
        DbUserProperty(
            key="phone_number",
            title="Phone",
            type=UserPropertyType.str,
            required=True,
            format=r"^((\+[0-9]{2}[- /\.]?([1-9][0-9]{2,5}))|(0[0-9]{3,4}))[-\s\./0-9]*[0-9]$",
            format_help="+49 1234 56789",
            can_edit=AccessType.self,
        ),
        DbUserProperty(
            key="phone_number_verified",
            title="Phone Verified",
            type=UserPropertyType.bool,
            can_edit=AccessType.admin,
        ),
        DbUserProperty(
            key="family_name",
            title="Family Name",
            type=UserPropertyType.str,
            required=True,
            format=r'^[\p{L} -]+$',
            format_help="printable characters",
            can_edit=AccessType.self,
        ),
        DbUserProperty(
            key="given_name",
            title="Given Name",
            type=UserPropertyType.str,
            required=True,
            format=r'^[\p{L} -]+$',
            format_help="printable characters",
            can_edit=AccessType.self,
        ),
        DbUserProperty(
            key="middle_name",
            title="Middle Name",
            type=UserPropertyType.str,
            format=r'^[\p{L} -]+$',
            format_help="printable characters",
            can_edit=AccessType.self,
            visible=AccessType.nobody,
        ),
        DbUserProperty(
            key="nickname",
            title="Nickname",
            type=UserPropertyType.str,
            format=r'^[\p{L} -]+$',
            format_help="printable characters",
            can_edit=AccessType.self,
            visible=AccessType.nobody,
        ),
        DbUserProperty(
            key="gender",
            title="Gender",
            type=UserPropertyType.enum,
            values=[
                DbEnumValue(value="female", title="Female"),
                DbEnumValue(value="male", title="Male"),
                DbEnumValue(value="non-binary", title="Non-Binary"),
                DbEnumValue(value="undefined", title="No Answer"),
            ],
            required=True,
            can_edit=AccessType.self,
        ),
        DbUserProperty(
            key="birthdate",
            title="Date of Birth",
            type=UserPropertyType.date,
            required=True,
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="zoneinfo",
            title="Zone Info",
            type=UserPropertyType.enum,
            values=[
                DbEnumValue(value="Europe/Berlin", title="Europe/Berlin"),
            ],
            default="Europe/Berlin",
            can_edit=AccessType.self,
            can_read=AccessType.self,
            visible=AccessType.admin,
        ),
        DbUserProperty(
            key="locale",
            title="Preferred Language",
            type=UserPropertyType.enum,
            values=[
                DbEnumValue(value="de_de", title="Deutsch"),
                DbEnumValue(value="en_us", title="English"),
            ],
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="profile",
            title="Profile URL",
            type=UserPropertyType.str,
            visible=AccessType.nobody,
            template="{config.oauth2.base_url}/profiles/{preferred_username}",
            protected=True,
        ),
        DbUserProperty(
            key="picture",
            title="Picture",
            type=UserPropertyType.picture,
            can_edit=AccessType.self,
            protected=True,
        ),
        DbUserProperty(
            key="website",
            title="Website",
            type=UserPropertyType.str,
            format=r'^https?://[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$',
            format_help="URL (e.g. https://example.com)",
            can_edit=AccessType.self,
            visible=AccessType.nobody,
            protected=True,
        ),
        DbUserProperty(
            key="street_address",
            title="Street Address",
            type=UserPropertyType.str,
            required=True,
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="region",
            title="State/Province",
            type=UserPropertyType.str,
            required=True,
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="locality",
            title="City",
            type=UserPropertyType.str,
            required=True,
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="postal_code",
            title="Postal Code",
            type=UserPropertyType.str,
            required=True,
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="country",
            title="Country",
            type=UserPropertyType.enum,
            values=[
                DbEnumValue(
                    value=key,
                    title=language,
                )
                for key, language in countries.items()
            ],
            default="DE",
            required=True,
            can_edit=AccessType.self,
            can_read=AccessType.self,
        ),
        DbUserProperty(
            key="password",
            title="Password",
            type=UserPropertyType.password,
            can_read=AccessType.nobody,
            can_edit=AccessType.self,
            required=True,
            protected=True,
        ),
        DbUserProperty(
            key="has_postbox",
            title="Enable Postbox",
            type=UserPropertyType.bool,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            default=False,
            protected=True,
        ),
        DbUserProperty(
            key="postbox_quota",
            title="Postbox Quota",
            type=UserPropertyType.int,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            format='^[0-9]+$',
            default=100000000,
            protected=True,
        ),
        DbUserProperty(
            key="access_tokens",
            title="Access Tokens",
            type=UserPropertyType.access_token,
            can_read=AccessType.self,
            can_edit=AccessType.self,
            default=[],
            protected=True,
        ),
        DbUserProperty(
            key="groups",
            title="User Groups",
            type=UserPropertyType.groups,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            default=['users'],
            protected=True,
        ),
        DbUserProperty(
            key="email_allowed_forward_groups",
            title="Allow Forward E-Mail",
            type=UserPropertyType.groups,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            visible=AccessType.nobody,
            default=[],
            protected=True,
        ),
        DbUserProperty(
            key="email_forward_groups",
            title="Forward E-Mail",
            type=UserPropertyType.groups,
            can_read=AccessType.self,
            can_edit=AccessType.self,
            visible=AccessType.nobody,
            default=[],
            protected=True,
        ),
        DbUserProperty(
            key="email_postbox_access_groups",
            title="Access Postbox",
            type=UserPropertyType.groups,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            visible=AccessType.nobody,
            default=[],
            protected=True,
        ),
        DbUserProperty(
            key="storage_quota",
            title="Storage Quota",
            type=UserPropertyType.int,
            can_read=AccessType.self,
            can_edit=AccessType.admin,
            format='^[0-9]+$',
            default=100000000,
        ),
        DbUserProperty(
            key="notes",
            title="Admin Notes",
            type=UserPropertyType.multistr,
            can_edit=AccessType.admin,
            can_read=AccessType.admin,
            format='^[0-9a-fA-F]*$'
        ),
        DbUserProperty(
            key="updated_at",
            title="Updated At",
            type=UserPropertyType.datetime,
            can_read=AccessType.self,
            visible=AccessType.admin,
            protected=True,
        ),
        DbUserProperty(
            key="card_id",
            title="Card ID",
            type=UserPropertyType.str,
            can_edit=AccessType.self,
            can_read=AccessType.admin,
            visible=AccessType.admin,
            format='^[0-9a-fA-F]*$'
        ),
    ],
    scopes=[
        DbUserScope(
            key='*',
            title='Global (additional to all scopes)',
            protected=True,
            properties=[
                DbUserScopeProperty(user_property="id", key="sub"),
            ],
        ),
        DbUserScope(
            key='profile',
            title='Profile',
            properties=[
                DbUserScopeProperty(user_property="name"),
                DbUserScopeProperty(user_property="family_name"),
                DbUserScopeProperty(user_property="given_name"),
                DbUserScopeProperty(user_property="middle_name"),
                DbUserScopeProperty(user_property="nickname"),
                DbUserScopeProperty(user_property="preferred_username"),
                DbUserScopeProperty(user_property="profile"),
                DbUserScopeProperty(user_property="picture"),
                DbUserScopeProperty(user_property="website"),
                # Separately below
                #UserScopeProperty(property="gender"),
                #UserScopeProperty(property="birthdate"),
                DbUserScopeProperty(user_property="zoneinfo"),
                # Separately below
                #UserScopeProperty(property="street_address", key="address.street_address"),
                #UserScopeProperty(property="locality", key="address.locality"),
                #UserScopeProperty(property="region", key="address.region"),
                #UserScopeProperty(property="postal_code", key="address.postal_code"),
                #UserScopeProperty(property="country", key="address.country"),
            ],
        ),
        DbUserScope(
            key='email',
            title='E-Mail',
            properties=[
                DbUserScopeProperty(user_property="email"),
                DbUserScopeProperty(user_property="email_verified"),
            ],
        ),
        DbUserScope(
            key='phone',
            title='Phone',
            properties=[
                DbUserScopeProperty(user_property="phone_number"),
                DbUserScopeProperty(user_property="phone_number_verified"),
            ],
        ),
        DbUserScope(
            key='gender',
            title='Gender',
            properties=[
                DbUserScopeProperty(user_property="gender"),
            ],
        ),
        DbUserScope(
            key='teams',
            title='Teams',
            properties=[
                DbUserScopeProperty(key="teams", user_property="groups", group_type="team"),
            ],
        ),
        DbUserScope(
            key='*users',
            title='Other Users Profile (special key)',
            protected=True,
            properties=[
                DbUserScopeProperty(user_property="name"),
                DbUserScopeProperty(user_property="family_name"),
                DbUserScopeProperty(user_property="given_name"),
                DbUserScopeProperty(user_property="picture"),
                DbUserScopeProperty(user_property="email"),
                DbUserScopeProperty(user_property="phone_number"),
            ],
        ),
        DbUserScope(
            key='birthdate',
            title='Birthdate',
            properties=[
                DbUserScopeProperty(user_property="birthdate"),
            ],
        ),
        DbUserScope(
            key='address',
            title='Address',
            properties=[
                DbUserScopeProperty(user_property="street_address", key="address.street_address"),
                DbUserScopeProperty(user_property="locality", key="address.locality"),
                DbUserScopeProperty(user_property="region", key="address.region"),
                DbUserScopeProperty(user_property="postal_code", key="address.postal_code"),
                DbUserScopeProperty(user_property="country", key="address.country"),
            ],
        ),
        DbUserScope(
            key='storage_quota',
            title='Storage Quota',
            properties=[
                DbUserScopeProperty(user_property="storage_quota"),
            ],
        ),
        DbUserScope(
            key='*ext_mail',
            title='E-Mail Authentication Access',
            protected=True,
            properties=[],
        ),
        DbUserScope(
            key='*ext_card_auth',
            title='Card Authentication Access',
            protected=True,
            properties=[],
        ),
    ],
    group_types=[
        DbGroupType(key='management', title="Management"),
        DbGroupType(key='team', title="Team"),
    ],
)

default_views = [
    DbUserView(
        id="all",
        name="List Users",
        protected=True,
        list_properties=[
            "email",
            "given_name",
            "family_name",
            "phone_number",
            "active",
        ],
        view_groups=[
            DbUserViewGroup(
                title="Profile Picture",
                user_properties=[
                    "picture",
                ],
            ),
            DbUserViewGroup(
                title="Account",
                user_properties=[
                    "id",
                    "active",
                    "preferred_username",
                ],
            ),
            DbUserViewGroup(
                type=UserGroupPropertyType.email,
                title="E-Mail",
                user_properties=[
                    "email",
                    "email_verified",
                    "has_email_alias",
                    "forward_emails",
                    "email_alias",
                ],
            ),
            DbUserViewGroup(
                title="Phone",
                user_properties=[
                    "phone_number",
                    "phone_number_verified",
                ],
            ),
            DbUserViewGroup(
                title="Name",
                user_properties=[
                    "name",
                    "family_name",
                    "given_name",
                    "middle_name",
                    "nickname",
                ],
            ),
            DbUserViewGroup(
                title="Personal",
                user_properties=[
                    "gender",
                    "birthdate",
                ],
            ),
            DbUserViewGroup(
                title="Language",
                user_properties=[
                    "zoneinfo",
                    "locale",
                ],
            ),
            DbUserViewGroup(
                title="Address",
                user_properties=[
                    "street_address",
                    "region",
                    "locality",
                    "postal_code",
                    "country",
                ]
            ),
            DbUserViewGroup(
                type=UserGroupPropertyType.password,
                title="Password",
                user_properties=[
                    "password",
                ],
            ),
            DbUserViewGroup(
                title="Postbox",
                user_properties=[
                    "has_postbox",
                    "postbox_quota",
                    "access_tokens",
                ],
            ),
            DbUserViewGroup(
                title="Groups",
                user_properties=[
                    "groups",
                    "email_allowed_forward_groups",
                    "email_forward_groups",
                    "email_postbox_access_groups",
                ],
            ),
            DbUserViewGroup(
                title="Other",
                user_properties=[
                    "profile",
                    "website",
                    "storage_quota",
                    "notes",
                    "updated_at",
                    "card_id",
                ],
            ),
        ],
    ),
    DbUserView(
        id="registration",
        name="Registration",
        protected=True,
        view_groups=[
            DbUserViewGroup(
                title="Account",
                user_properties=[
                    "picture",
                    "email",
                    "password",
                    "active",
                ],
            ),
            DbUserViewGroup(
                title="Personal",
                user_properties=[
                    "given_name",
                    "family_name",
                    "phone_number",
                    "birthdate",
                    "gender",
                ],
            ),
            DbUserViewGroup(
                title="Address",
                user_properties=[
                    "street_address",
                    "postal_code",
                    "locality",
                    "region",
                    "country",
                ],
            ),
        ]
    ),
    DbUserView(
        id="new",
        name="New User (Admin)",
        protected=True,
        view_groups=[
            DbUserViewGroup(
                title="Account",
                user_properties=[
                    "email",
                    "active",
                ],
            ),
            DbUserViewGroup(
                title="Personal",
                user_properties=[
                    "given_name",
                    "family_name",
                    "phone_number",
                    "birthdate",
                    "gender",
                ],
            ),
            DbUserViewGroup(
                title="Address",
                user_properties=[
                    "street_address",
                    "postal_code",
                    "locality",
                    "region",
                    "country",
                ],
            ),
        ]
    )
]
