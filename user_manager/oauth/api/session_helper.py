import os

from authlib.common.urls import add_params_to_uri
from starlette.responses import Response

from user_manager.common.config import config
from user_manager.oauth.oauth2 import RedirectResponse
from user_manager.oauth.user_helper import UserWithRoles

COOKIE_KEY_SID = 'OAUTH_SID'
COOKIE_KEY_STATE = 'OAUTH_STATE'


def add_session_state(response: RedirectResponse, user: UserWithRoles):
    response.headers['location'] = add_params_to_uri(
        response.headers['location'], [('session_state', user.last_modified)]
    )


def update_session_sid(response: Response, session_id: str):
    response.set_cookie(
        key=COOKIE_KEY_SID,
        value=session_id,
        max_age=config.oauth2.token_expiration.session,
        secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
    )


def update_session_state(response: Response, user: UserWithRoles):
    response.set_cookie(
        key=COOKIE_KEY_STATE,
        value=str(user.last_modified),
        max_age=config.oauth2.token_expiration.session,
        secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
    )
