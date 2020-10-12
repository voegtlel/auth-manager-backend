from typing import Tuple

import gridfs
from fastapi import HTTPException, APIRouter
from fastapi.params import Header
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from user_manager.common.mongo import async_user_picture_bucket
from .cors_helper import allow_all_get_head_cors

router = APIRouter()


async def _async_get_picture(
        picture_id: str,
        if_none_match: str = Header(None),
        if_match: str = Header(None),
) -> Tuple[gridfs.GridOut, dict]:
    try:
        stream = await async_user_picture_bucket.open_download_stream(picture_id)
    except gridfs.errors.NoFile:
        raise HTTPException(404)
    file_hash = stream.metadata['hash'].hex()
    if if_none_match is not None and file_hash in [m.strip() for m in if_none_match.split(',')]:
        stream.close()
        raise HTTPException(304)
    if if_match is not None and file_hash not in [m.strip() for m in if_match.split(',')]:
        stream.close()
        raise HTTPException(304)
    return stream, {'ETag': file_hash}


@router.options('/picture/{picture_id}')
async def get_picture_options(request: Request):
    return allow_all_get_head_cors.options(request)


@router.head(
    '/picture/{picture_id}',
    tags=['User Manager'],
)
async def get_picture_meta(
        picture_id: str,
        if_none_match: str = Header(None),
        if_match: str = Header(None),
):
    """Get picture metadata."""
    try:
        stream, headers = await _async_get_picture(picture_id, if_none_match, if_match)
        stream.close()
    except HTTPException as e:
        return Response(status_code=e.status_code)
    return Response(status_code=200, headers=headers)


@router.get(
    '/picture/{picture_id}',
    tags=['User Manager'],
)
async def get_picture(
        picture_id: str,
        if_none_match: str = Header(None),
        if_match: str = Header(None),
):
    """Get picture data."""
    try:
        stream, headers = await _async_get_picture(picture_id, if_none_match, if_match)
    except HTTPException as e:
        return Response(status_code=e.status_code)

    async def stream_iterator():
        while True:
            chunk = await stream.readchunk()
            if not chunk:
                break
            yield chunk
        stream.close()

    return StreamingResponse(
        stream_iterator(), media_type=stream.metadata['content_type'], headers=headers
    )
