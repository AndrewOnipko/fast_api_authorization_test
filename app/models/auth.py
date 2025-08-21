from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

# Оставляем на всякий случай, если пригодится для non-browser клиентов
class TokenPair(BaseModel):
    access_token: str
    refresh_token: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    # Можно взять из cookie, если не передали в теле
    refresh_token: str | None = None

class LogoutRequest(BaseModel):
    # Можно взять из cookie, если не передали в теле
    refresh_token: str | None = None

# Ответ для cookie-only режима
class AuthOk(BaseModel):
    detail: str = "ok"
    access_expires_in: int  # сек
    refresh_expires_in: int  # сек

class UserOut(BaseModel):
    id: str
    email: EmailStr
    is_active: bool
    is_superuser: bool
    created_at: datetime
