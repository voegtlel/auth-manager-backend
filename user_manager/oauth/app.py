from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from user_manager.common.config import config
from user_manager.oauth.api import router

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=config.manager.secret_key)

app.include_router(router)
