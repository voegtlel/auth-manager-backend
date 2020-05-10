from fastapi import FastAPI, APIRouter
from starlette.middleware.cors import CORSMiddleware

from user_manager.common.config import config
from user_manager.manager.api.user import router as user_router
from user_manager.manager.api.group import router as group_router
from user_manager.manager.api.client import router as client_router

router = APIRouter()
router.include_router(user_router)
router.include_router(group_router)
router.include_router(client_router)

app = FastAPI(openapi_prefix='/manager')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.manager.backend_cors_origin],
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allow_headers=['*'],
)

app.include_router(router)
