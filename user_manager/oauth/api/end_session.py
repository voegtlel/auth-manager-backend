from typing import Optional

from fastapi import APIRouter
from fastapi.params import Query, Cookie, Header

from user_manager.common.mongo import async_session_collection, async_token_collection
from user_manager.oauth.oauth2 import RedirectResponse
from .session_helper import COOKIE_KEY_SID, COOKIE_KEY_STATE

router = APIRouter()


@router.get(
    '/end_session',
    responses={
        302: {'description': 'Redirect to result'},
    },
)
async def end_session(
        id_token_hint: Optional[str] = Query(None),
        post_logout_redirect_uri: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
        sid: Optional[str] = Cookie(None, alias=COOKIE_KEY_SID),
        referer: Optional[str] = Header(None),
):
    """Ends the session."""
    if sid is not None:
        await async_session_collection.delete_one({'_id': sid})
    if id_token_hint is not None:
        await async_token_collection.delete_one({'access_token': id_token_hint})
    if post_logout_redirect_uri is not None:
        if state is not None:
            if '#' in post_logout_redirect_uri:
                post_logout_redirect_uri, post_logout_redirect_hash = post_logout_redirect_uri.split('#', 1)
                post_logout_redirect_hash = '#' + post_logout_redirect_hash
            else:
                post_logout_redirect_hash = ''
            if '?' in post_logout_redirect_uri[:-1]:
                post_logout_redirect_uri += '&state=' + state
            else:
                post_logout_redirect_uri += '?state=' + state
            post_logout_redirect_uri += post_logout_redirect_hash
    elif referer is not None:
        post_logout_redirect_uri = referer
    else:
        post_logout_redirect_uri = ''
    response = RedirectResponse(
        status_code=302,
        headers={'Location': post_logout_redirect_uri},
    )
    response.delete_cookie(COOKIE_KEY_SID)
    response.delete_cookie(COOKIE_KEY_STATE)
    return response
