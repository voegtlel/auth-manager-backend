import os

from fastapi import APIRouter
from starlette.responses import FileResponse

router = APIRouter()

status_iframe_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'status-iframe.html')


@router.get(
    '/login-status-iframe.html',
    tags=['OAuth2 Provider: Status IFrame'],
)
async def get_login_status_iframe():
    return FileResponse(status_iframe_path, media_type='text/html')
