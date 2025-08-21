from __future__ import annotations
from fastapi import Depends, HTTPException, Request, status

from app.core.db import get_pool
from app.core.security import decode_token
from app.core.config import settings
from app.repositories.users import UsersRepo
from app.core.logger import get_logger

log = get_logger()

async def get_current_user(request: Request):
    """Достаёт текущего пользователя по access токену.
    Токен ищется так:
      1) В заголовке Authorization: Bearer <token>
      2) Если нет - в cookie (ACCESS_COOKIE_NAME)
    Если что-то не так - кидаем 401."""

    # Пробуем взять из заголовка
    auth = request.headers.get("Authorization", "")
    prefix = "Bearer "
    token = auth[len(prefix):].strip() if auth.startswith(prefix) else None

    # Если в заголовке пусто — пробуем cookie
    if not token:
        token = request.cookies.get(settings.ACCESS_COOKIE_NAME)

    if not token:
        log.warning("auth missing token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    payload = decode_token(token)
    if payload.get("type") != "access":
        log.warning("auth wrong token type")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")

    user_id = payload.get("sub")
    pool = get_pool(request.app)
    user = await UsersRepo(pool).get_by_id(user_id)
    if not user or not user["is_active"]:
        log.warning("auth user not found or inactive user_id=%s", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user
