import uuid
from typing import Annotated

from fastapi import APIRouter, Cookie, Request, Response

from paseto_forge.api.dependencies import (
    AuthServiceDep,
    CurrentUserDep,
    PasetoServiceDep,
    TokenPayloadDep,
)
from paseto_forge.exceptions import TokenInvalidError
from paseto_forge.schemas import (
    LoginRequest,
    PublicKeyResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(body: RegisterRequest, auth_service: AuthServiceDep):
    user = await auth_service.register(body.email, body.password)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    auth_service: AuthServiceDep,
    response: Response,
    request: Request,
):
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    access_token, refresh_token = await auth_service.login(
        body.email, body.password, device_info, ip_address
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/api/v1/auth",
        max_age=30 * 86400,
    )

    return TokenResponse(access_token=access_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    auth_service: AuthServiceDep,
    request: Request,
    response: Response,
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if not refresh_token:
        raise TokenInvalidError(detail="No refresh token cookie present")

    access_token, new_refresh = await auth_service.refresh(refresh_token)

    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/api/v1/auth",
        max_age=30 * 86400,
    )

    return TokenResponse(access_token=access_token)


@router.post("/logout", status_code=204)
async def logout(
    payload: TokenPayloadDep,
    auth_service: AuthServiceDep,
    response: Response,
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    await auth_service.logout_with_refresh(payload.jti, payload.exp, refresh_token)
    response.delete_cookie(key="refresh_token", path="/api/v1/auth")


@router.post("/logout-all", status_code=204)
async def logout_all(
    payload: TokenPayloadDep,
    auth_service: AuthServiceDep,
):
    await auth_service.logout_all(uuid.UUID(payload.sub))


@router.get("/me", response_model=UserResponse)
async def me(current_user: CurrentUserDep):
    return current_user


@router.get("/.well-known/paseto-public-key", response_model=PublicKeyResponse)
async def public_key(paseto_service: PasetoServiceDep):
    return PublicKeyResponse(key=paseto_service.public_key_paserk)
