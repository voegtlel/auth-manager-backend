import traceback

from fastapi import FastAPI, APIRouter, Request, Response
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import StreamingResponse

from user_manager.common.config import config
from user_manager.manager.api.client import router as client_router
from user_manager.manager.api.group import router as group_router
from user_manager.manager.api.schema import router as schema_router
from user_manager.manager.api.user import router as user_router
from user_manager.manager.api.user_history import router as user_history_router
from user_manager.manager.api.user_view import router as user_view_router

router = APIRouter()
router.include_router(user_router)
router.include_router(group_router)
router.include_router(client_router)
router.include_router(schema_router)
router.include_router(user_view_router)
router.include_router(user_history_router)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.manager.backend_cors_origin,
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allow_headers=['*'],
)
app.include_router(router)


@app.middleware('http')
async def catch_exceptions_middleware(request: Request, call_next):
    try:
        resp = await call_next(request)
        if isinstance(resp, StreamingResponse):
            async def stream_print():
                async for chunk in resp.body_iterator:
                    print(f"Body: {chunk}")
                    yield chunk

            print(f"Header: {resp.headers}")
            return StreamingResponse(
                stream_print(),
                resp.status_code,
                headers=dict(resp.headers),
                media_type=resp.media_type,
                background=resp.background,
            )
        elif isinstance(resp, Response):
            if resp.status_code >= 400:
                print(f"Header: {resp.headers}")
                print(f"Body: {resp.body}")
        return resp
    except Exception:
        traceback.print_exc()
        return Response("Internal server error", status_code=500)
