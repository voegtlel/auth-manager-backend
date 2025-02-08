from fastapi import APIRouter

from . import (
    authorize,
    end_session,
    login_status,
    picture,
    token,
    userinfo,
    well_known,
    ext_card_auth,
    ext_edge_sync,
    ext_profiles,
    ext_mail,
    ext_mailing_list,
)

router = APIRouter()
router.include_router(authorize.router)
router.include_router(end_session.router)
router.include_router(login_status.router)
router.include_router(picture.router)
router.include_router(token.router)
router.include_router(userinfo.router)
router.include_router(well_known.router)
router.include_router(ext_card_auth.router)
router.include_router(ext_edge_sync.router)
router.include_router(ext_profiles.router)
router.include_router(ext_mail.router)
router.include_router(ext_mailing_list.router)
