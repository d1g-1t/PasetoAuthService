import re

from pydantic import BaseModel, EmailStr, field_validator, model_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    password_confirm: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Min 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("At least one uppercase letter required")
        if not re.search(r"\d", v):
            raise ValueError("At least one digit required")
        if not re.search(r"[!@#$%^&*()\-_=+{}\[\]:;\"'<>,.?/\\|`~]", v):
            raise ValueError("At least one special character required")
        return v

    @model_validator(mode="after")
    def check_passwords_match(self) -> "RegisterRequest":
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PublicKeyResponse(BaseModel):
    version: str = "v4"
    purpose: str = "public"
    key: str
