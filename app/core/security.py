from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4, UUID

import jwt
from fastapi import HTTPException, status
from passlib.hash import argon2

from app.core.config import settings
from app.core.logger import get_logger

log = get_logger()

def hash_password(password: str) -> str:
    """Делаем хеш пароля"""

    hashed = argon2.hash(password)
    log.debug("password hashed")
    return hashed


def verify_password(password: str, password_hash: str) -> bool:
    """Проверяем, что пароль подходит к хешу (true/false)."""
    
    ok = argon2.verify(password, password_hash)
    log.debug("password verify ok=%s", ok)
    return ok


def _now() -> datetime:
    """Возвращает текущее время в UTC. Нужен для полей iat/exp."""

    return datetime.now(timezone.utc)


def create_access_token(user_id: str, email: str) -> str:
    """Создаем короткоживущий токен доступа"""
    iat = int(_now().timestamp())
    exp = int((_now() + settings.access_delta()).timestamp())
    jti = str(uuid4())
    payload = {"sub": user_id, "email": email, "type": "access",
               "iat": iat, "exp": exp, "jti": jti}
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)
    log.debug("access created user_id=%s jti=%s", user_id, jti)
    return token


def create_refresh_token(user_id: str, email: str, jti: Optional[UUID] = None) -> tuple[str, UUID, int]:
    """Создаем длинноживущий рефреш токен
    Возвращает кортеж: (сам токен, jti, exp_timestamp)
    jti мы сохраняем в БД, чтобы можно было ревокнуть/проверить."""

    iat = int(_now().timestamp())
    exp_dt = _now() + settings.refresh_delta()
    exp = int(exp_dt.timestamp())
    jti_val = jti or uuid4()
    payload = {"sub": user_id, "email": email, "type": "refresh",
               "iat": iat, "exp": exp, "jti": str(jti_val)}
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)
    log.debug("refresh created user_id=%s jti=%s", user_id, str(jti_val))
    return token, jti_val, exp


def decode_token(token: str) -> dict[str, Any]:
    """Декодируем JWT и проверяет его подпись/срок.
    Если просрочен или сломан — кидает 401."""

    try:
        data = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        t = data.get("type")
        log.debug("token decoded ok type=%s", t)
        return data
    except jwt.ExpiredSignatureError:
        log.warning("token expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        log.warning("invalid token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")