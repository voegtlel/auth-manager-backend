from typing import Optional, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from user_manager.common.mongo import async_user_collection

router = APIRouter()


class PassdbDict(BaseModel):
    password: Optional[str]
    nopassword: Optional[Literal['Y']]
    allow_nets: str


@router.get(
    '/dovecot/passdb/{user_email:path}',
    response_model=PassdbDict
)
def passdb_dict(user_email: str):
    user_data = await async_user_collection.find_one({'email': user_email})
    if user_data is None:
        raise HTTPException(404)
    return PassdbDict(password=None, nopassword='Y', allow_nets=)
