from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

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
    refresh_token: str | None = None

class LogoutRequest(BaseModel):
    refresh_token: str | None = None

class AuthOk(BaseModel):
    detail: str = "ok"
    access_expires_in: int  
    refresh_expires_in: int  

class UserOut(BaseModel):
    id: str
    email: EmailStr
    is_active: bool
    is_superuser: bool
    created_at: datetime
