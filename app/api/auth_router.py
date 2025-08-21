from __future__ import annotations
from typing import cast
from fastapi import APIRouter, Request, Response, HTTPException, status

from app.core.db import get_pool
from app.core.config import settings
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from app.models.auth import LoginRequest, RegisterRequest, RefreshRequest, AuthOk

from app.repositories.users import UsersRepo
from app.repositories.refresh_tokens import RefreshTokensRepo
from app.docs.auth_docs import AuthDocs
from app.core.logger import get_logger

log = get_logger()
router = APIRouter()

@router.post("/register", **AuthDocs.register)
async def register(req: Request, body: RegisterRequest, resp: Response) -> AuthOk:
    """Регистрируем нового пользователя:
    - проверяем, что такого email ещё нет
    - хешируем пароль
    - создаём запись в БД
    - выдаём токены и ставим cookies"""

    pool = get_pool(req.app)
    users = UsersRepo(pool)

    existing = await users.get_by_email(body.email)
    if existing:
        log.warning("register conflict email=%s", body.email)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    pwd_hash = hash_password(body.password)
    user = await users.create(email=body.email, password_hash=pwd_hash)

    access = create_access_token(user_id=str(user["id"]), email=user["email"])
    refresh_token, jti, exp = create_refresh_token(user_id=str(user["id"]), email=user["email"])
    await RefreshTokensRepo(pool).issue(user_id=user["id"], jti=jti, exp_ts=exp, 
                                        ip=_ip(req), user_agent=_ua(req))

    _set_auth_cookies(resp, access, refresh_token)
    log.info("register ok user_id=%s email=%s", str(user["id"]), user["email"])
    return AuthOk(access_expires_in=settings.ACCESS_TOKEN_TTL,
                  refresh_expires_in=settings.REFRESH_TOKEN_TTL)


@router.post("/login", **AuthDocs.login)
async def login(req: Request, body: LoginRequest, resp: Response) -> AuthOk:
    """Логин:
    - ищем пользователя по email
    - проверяем пароль
    - выдаём новую пару токенов (access+refresh)
    - записываем refresh jti в БД и ставим cookies"""

    pool = get_pool(req.app)
    users = UsersRepo(pool)

    user = await users.get_by_email(body.email)
    if not user or not verify_password(body.password, user["password_hash"]):
        log.warning("login failed email=%s", body.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access = create_access_token(user_id=str(user["id"]), email=user["email"])
    refresh_token, jti, exp = create_refresh_token(user_id=str(user["id"]), email=user["email"])
    await RefreshTokensRepo(pool).issue(user_id=user["id"], jti=jti, exp_ts=exp, 
                                        ip=_ip(req), user_agent=_ua(req))

    _set_auth_cookies(resp, access, refresh_token)
    log.info("login ok user_id=%s email=%s", str(user["id"]), user["email"])
    return AuthOk(access_expires_in=settings.ACCESS_TOKEN_TTL,
                  refresh_expires_in=settings.REFRESH_TOKEN_TTL)


@router.post("/refresh", **AuthDocs.refresh)
async def refresh(req: Request, body: RefreshRequest, resp: Response) -> AuthOk:
    """Обновление токенов (ротация refresh):
    - берём refresh из тела или из cookie
    - проверяем валидность JWT и сверяем jti в БД
    - помечаем старый refresh как revoked
    - выдаём новую пару токенов и записываем новый jti в БД"""

    pool = get_pool(req.app)
    repo = RefreshTokensRepo(pool)

    rt = body.refresh_token or req.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not rt:
        log.warning("refresh missing token")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing refresh token")

    payload = decode_token(rt)
    if payload.get("type") != "refresh":
        log.warning("refresh wrong type")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong token type")

    jti = payload.get("jti")
    user_id = payload.get("sub")

    db_token = await repo.get_by_jti(cast(str, jti))
    if not db_token or db_token["revoked_at"] is not None:
        log.warning("refresh invalid_or_revoked jti=%s", jti)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalid or revoked")

    await repo.revoke(jti=cast(str, jti), reason="rotated")

    users = UsersRepo(pool)
    user = await users.get_by_id(user_id)
    if not user:
        log.warning("refresh user_missing user_id=%s", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    access = create_access_token(user_id=str(user["id"]), email=user["email"])
    new_refresh, new_jti, exp = create_refresh_token(user_id=str(user["id"]), email=user["email"])
    await repo.issue(user_id=user["id"], jti=new_jti, exp_ts=exp, ip=_ip(req), user_agent=_ua(req))

    _set_auth_cookies(resp, access, new_refresh)
    log.info("refresh rotated user_id=%s old_jti=%s new_jti=%s", str(user["id"]), jti, str(new_jti))
    return AuthOk(access_expires_in=settings.ACCESS_TOKEN_TTL,
                  refresh_expires_in=settings.REFRESH_TOKEN_TTL)


@router.post("/logout", **AuthDocs.logout)
async def logout(req: Request, body: RefreshRequest, resp: Response):
    """Логаут:
    - берём refresh из тела или из cookie
    - помечаем его как revoked (если был)
    - чистим cookies"""

    pool = get_pool(req.app)
    repo = RefreshTokensRepo(pool)

    rt = body.refresh_token or req.cookies.get(settings.REFRESH_COOKIE_NAME)
    if rt:
        payload = decode_token(rt)
        if payload.get("type") != "refresh":
            log.warning("logout wrong type")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong token type")
        jti = payload.get("jti")
        await repo.revoke(jti=jti, reason="logout")
        log.info("logout revoked jti=%s", jti)
    else:
        log.info("logout without token (just clearing cookies)")

    _clear_auth_cookies(resp)
    return {"detail": "ok"}


def _set_auth_cookies(resp: Response, access: str, refresh: str) -> None:
    """Устанавливает две HttpOnly cookies:
    - access_token (короткий срок)
    - refresh_token (длинный срок)
    Параметры берём из settings (Secure, SameSite и т.д.)."""

    cookie_kwargs = dict(domain=settings.COOKIE_DOMAIN, path=settings.COOKIE_PATH, 
                         secure=settings.COOKIE_SECURE, httponly=True, samesite=settings.COOKIE_SAMESITE)
    resp.set_cookie(settings.ACCESS_COOKIE_NAME, access, max_age=settings.ACCESS_TOKEN_TTL, **cookie_kwargs)
    resp.set_cookie(settings.REFRESH_COOKIE_NAME, refresh, max_age=settings.REFRESH_TOKEN_TTL, **cookie_kwargs)


def _clear_auth_cookies(resp: Response) -> None:
    """Удаляет обе cookies авторизации (делаем на logout)."""

    for name in (settings.ACCESS_COOKIE_NAME, settings.REFRESH_COOKIE_NAME):
        resp.delete_cookie(name, domain=settings.COOKIE_DOMAIN, path=settings.COOKIE_PATH, samesite=settings.COOKIE_SAMESITE)


def _ip(req: Request) -> str | None:
    """Пытаемся угадать IP клиента (берём X-Forwarded-For или адрес сокета)."""

    return req.headers.get("X-Forwarded-For") or req.client.host if req.client else None


def _ua(req: Request) -> str | None:
    """User-Agent клиента. Полезно для аудита refresh токенов."""

    return req.headers.get("User-Agent")
