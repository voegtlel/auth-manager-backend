from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from starlette.requests import Request

from user_manager.oauth.oauth2 import request_origin_verifier, edge_sync
from .cors_helper import allow_all_get_cors
from .ext_auth_base import AuthenticateClient
from .oauth2_helper import oauth2_request
from ...common.models import DbClient

router = APIRouter()


client_auth = AuthenticateClient('*edge_sync')


@router.options(
    '/edge-sync',
    include_in_schema=False,
    tags=['Extension: Edge-Sync'],
)
async def get_edge_sync_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/edge-sync',
    tags=['Extension: Edge-Sync'],
    response_model=List[Dict[str, Any]],
)
async def get_edge_sync(
        request: Request,
        last_sync: int = Query(),
        client: Optional[dict] = Depends(client_auth),
):
    """List profiles since modification for synchronization."""
    oauth_request = await oauth2_request(request)
    if client is not None:
        oauth_request.data['client_id'] = client['_id']
        oauth_request.client = DbClient.validate_document(client)
    origin = request.headers.get("origin")
    if origin is not None:
        origin_response = await request_origin_verifier.create_response(oauth_request, origin)
        if origin_response is not None:
            allow_all_get_cors.augment(request, origin_response)
            return origin_response
    response = await edge_sync.create_response(oauth_request, since_modification=last_sync)
    allow_all_get_cors.augment(request, response)
    return response
