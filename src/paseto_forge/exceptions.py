class PasetoAuthServiceError(Exception):
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"
    detail: str = "Internal server error"

    def __init__(self, detail: str | None = None):
        if detail:
            self.detail = detail
        super().__init__(self.detail)


class AuthenticationError(PasetoAuthServiceError):
    status_code = 401
    error_code = "AUTHENTICATION_FAILED"
    detail = "Authentication failed"


class TokenExpiredError(AuthenticationError):
    error_code = "TOKEN_EXPIRED"
    detail = "Token has expired"


class TokenInvalidError(AuthenticationError):
    error_code = "TOKEN_INVALID"
    detail = "Invalid token"


class TokenRevokedError(AuthenticationError):
    error_code = "TOKEN_REVOKED"
    detail = "Token has been revoked"


class RefreshTokenReuseError(AuthenticationError):
    error_code = "REFRESH_TOKEN_REUSE_DETECTED"
    detail = "Refresh token reuse detected — token family revoked"


class PermissionDeniedError(PasetoAuthServiceError):
    status_code = 403
    error_code = "PERMISSION_DENIED"
    detail = "Insufficient permissions"


class UserNotFoundError(PasetoAuthServiceError):
    status_code = 404
    error_code = "USER_NOT_FOUND"
    detail = "User not found"


class UserAlreadyExistsError(PasetoAuthServiceError):
    status_code = 409
    error_code = "USER_ALREADY_EXISTS"
    detail = "User already exists"


class AccountLockedError(AuthenticationError):
    error_code = "ACCOUNT_LOCKED"
    detail = "Account temporarily locked"
