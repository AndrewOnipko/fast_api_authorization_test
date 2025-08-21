from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class UserOut(BaseModel):
    id: str
    email: EmailStr
    is_active: bool
    is_superuser: bool
    created_at: datetime


class UpdatePasswordRequest(BaseModel):
    email: EmailStr
    current_password: str = Field(min_length=1, description="Текущий пароль")
    new_password: str = Field(min_length=8, max_length=128, description="Новый пароль, минимум 8 символов")


class DeleteByEmailRequest(BaseModel):
    email: EmailStr
