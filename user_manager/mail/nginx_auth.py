import ipaddress
import socket
import urllib.parse
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from user_manager.common.config import config
from user_manager.common.mongo import async_user_collection, async_user_group_collection
from user_manager.common.throttle import async_throttle_delay, async_throttle_failure
from user_manager.mail.api import MailTokenAuthentication, EmailUser

router = APIRouter()


class AuthMethod(Enum):
    none = "none"
    plain = "plain"
    apop = "apop"
    cram_md5 = "cram-md5"
    external = "external"


class AuthProtocol(Enum):
    imap = "imap"
    pop3 = "pop3"
    smtp = "smtp"


_default_ports = {
    AuthProtocol.imap: 143,
    AuthProtocol.pop3: 110,
    AuthProtocol.smtp: 25
}

_auth_failure_message = {
    AuthProtocol.imap: "AUTHENTICATIONFAILED",
    AuthProtocol.pop3: "-ERR Authentication failed",
    AuthProtocol.smtp: "535 5.7.8",
}


async def _auth_error(client_ip: str, auth_protocol: AuthProtocol) -> Response:
    _, delay = await async_throttle_failure(client_ip)
    return Response(
        headers={
            'Auth-Status': "Authentication credentials invalid",
            'Auth-Error-Code': _auth_failure_message[auth_protocol],
            'Auth-Wait': delay,
        }
    )


def _auth_success(x_auth_server: str, auth_port: str) -> Response:
    return Response(
        headers={
            'Auth-Status': 'OK',
            'Auth-Server': x_auth_server,
            'Auth-Port': auth_port
        }
    )


@router.get(
    '/nginx/auth',
    tags=['NGinx Auth'],
    dependencies=[Depends(MailTokenAuthentication())],
    response_model=None,
)
async def nginx_auth(
        auth_method: AuthMethod = Header(...),
        auth_protocol: AuthProtocol = Header(...),
        auth_user: Optional[str] = Header(None),
        auth_pass: Optional[str] = Header(None),
        auth_login_attempt: int = Header(1),
        client_ip: str = Header(...),
        client_host: str = Header(...),
        x_auth_server: str = Header(...),
) -> Response:
    """
    Authentication for nginx `auth_http`. Use like::

        auth_http http://myserver/nginx/auth;
        auth_http_header X-Api-Key "YourSecret";
        auth_http_header X-Auth-Server "target-mailserver-host[:1234]";
        auth_http_pass_client_cert off;
        auth_http_timeout 60s;
    """

    if auth_login_attempt > 10:
        return Response(
            headers={'Auth-Status': 'Invalid login or password'},
        )

    client_ip = urllib.parse.unquote(client_ip)

    throttle_delay = await async_throttle_delay(client_ip)
    if throttle_delay > 0:
        return Response(
            headers={
                'Auth-Status': 'Invalid login or password',
                'Auth-Wait': max(int(throttle_delay), 1),
            }
        )

    if ':' in x_auth_server:
        x_auth_server, auth_port = x_auth_server.rsplit(':')
    else:
        auth_port = None
    auth_port = auth_port or _default_ports[auth_protocol]
    try:
        ipaddress.ip_address(x_auth_server)
    except ValueError:
        x_auth_server = await run_in_threadpool(socket.gethostbyname, x_auth_server)

    if auth_method == AuthMethod.none and auth_protocol == AuthProtocol.smtp:
        return _auth_success(x_auth_server, auth_port)
    elif auth_method == AuthMethod.plain:
        if auth_user is None or auth_pass is None:
            raise HTTPException(400, "Missing Auth-User or Auth-Pass")

        raw_user = urllib.parse.unquote(auth_user)
        address = raw_user.encode("iso8859-1").decode("utf8")
        raw_password = urllib.parse.unquote(auth_pass)
        password = raw_password.encode("iso8859-1").decode("utf8")

        address = address.lower()
        if '@' not in address:
            return await _auth_error(client_ip, auth_protocol)
        mail_name, domain = address.split('@', 1)
        if domain != config.oauth2.mail_domain:
            return await _auth_error(client_ip, auth_protocol)

        if len(password) < 8:
            return await _auth_error(client_ip, auth_protocol)
        result = await async_user_collection.find_one(
            {'email_postbox_access_token': password},
            EmailUser.__mongo_attrs__,
        )
        if result is None:
            return await _auth_error(client_ip, auth_protocol)
        email_user = EmailUser.validate(result)
        if email_user.has_postbox and address == email_user.email_alias:
            return _auth_success(x_auth_server, auth_port)
        if auth_protocol in (AuthProtocol.imap, AuthProtocol.pop3):
            if await async_user_group_collection.count_documents(
                {
                    '_id': mail_name,
                    'email_postbox_access_members': email_user.id,
                    'enable_postbox': True,
                    'enable_email': True,
                }
            ) == 0:
                return await _auth_error(client_ip, auth_protocol)
        elif auth_protocol == AuthProtocol.smtp:
            if await async_user_group_collection.count_documents(
                    {
                        '_id': mail_name,
                        'enable_email': True,
                        '$or': [
                            {'email_allowed_forward_members': email_user.id},
                            {'email_postbox_access_members': email_user.id},
                        ],
                    }
            ) == 0:
                return await _auth_error(client_ip, auth_protocol)
        return _auth_success(x_auth_server, auth_port)
    raise HTTPException(400, "Invalid request")
