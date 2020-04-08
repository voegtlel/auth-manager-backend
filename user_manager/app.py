from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from user_manager.common.config import config
from user_manager.oauth.api import router as oauth_router
from user_manager.manager.api import router as manager_router

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=config.manager.secret_key)

app.include_router(oauth_router)
app.include_router(manager_router, prefix='/manager')
