from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from user_manager.common.config import config
from user_manager.mail.api import router

app = FastAPI(openapi_prefix='/mail')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.manager.backend_cors_origin],
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allow_headers=['*'],
)

app.include_router(router)
