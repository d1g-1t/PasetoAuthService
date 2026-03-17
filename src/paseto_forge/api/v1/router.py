from fastapi import APIRouter

from paseto_forge.api.v1.auth import router as auth_router

router = APIRouter()
router.include_router(auth_router)
