from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.logger import get_logger
from app.core.security import verify_password, hash_password
from app.models.users import UserOut, UpdatePasswordRequest, DeleteByEmailRequest
from app.repositories.users import UsersRepo
from app.repositories.refresh_tokens import RefreshTokensRepo
from app.core.db import get_pool
from app.docs.users_docs import UsersDocs

router = APIRouter()
log = get_logger()


@router.get("/me", **UsersDocs.me)
async def me(user = Depends(get_current_user)) -> UserOut:
    """Возвращает данные текущего пользователя."""
    return UserOut(id=str(user["id"]), email=user["email"], is_active=user["is_active"], 
                   is_superuser=user["is_superuser"], created_at=user["created_at"])


@router.patch("/me/password", **UsersDocs.update_password)
async def update_password(request: Request, response: Response, body: UpdatePasswordRequest, user = Depends(get_current_user)):
    """Меняем пароль только для самого себя.
    Проверяем:
      - что email из тела совпадает с email авторизованного пользователя
      - что текущий пароль верный
    После смены пароля:
      - отзывает все refresh токены пользователя (logout во всех сессиях)
      - очищает cookies в ответе"""
    
    if body.email != user["email"]:
        log.warning("update_password forbidden email_mismatch body=%s user=%s", body.email, user["email"])
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email is not your own")

    pool = get_pool(request.app)
    users_repo = UsersRepo(pool)
    target = await users_repo.get_by_email(body.email)
    if not target:
        log.warning("update_password user_not_found email=%s", body.email)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not verify_password(body.current_password, target["password_hash"]):
        log.warning("update_password wrong_current_password email=%s", body.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is wrong")

    new_hash = hash_password(body.new_password)
    ok = await users_repo.update_password_by_id(user_id=target["id"], new_password_hash=new_hash)
    if not ok:
        log.warning("update_password failed_to_update user_id=%s", str(target["id"]))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update password")

    await RefreshTokensRepo(pool).revoke_all_for_user(user_id=target["id"], reason="password_change")

    _clear_auth_cookies(response)

    log.info("update_password ok user_id=%s email=%s", str(target["id"]), target["email"])
    return {"detail": "ok"}


@router.delete("/me", **UsersDocs.delete_me)
async def delete_me(request: Request, response: Response, user = Depends(get_current_user)):
    """Удаляем текущий аккаунт. Перед удалением отзываем все refresh-токены. После — чистим cookies."""

    pool = get_pool(request.app)
    users_repo = UsersRepo(pool)

    await RefreshTokensRepo(pool).revoke_all_for_user(user_id=user["id"], reason="user_delete")

    deleted = await users_repo.delete_by_email(user["email"])
    if not deleted:
        log.warning("delete user_not_found email=%s", user["email"])
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    _clear_auth_cookies(response)
    log.info("delete ok email=%s", user["email"])
    return {"detail": "ok"}


def _clear_auth_cookies(resp: Response) -> None:
    """Удаляет обе auth cookies (access/refresh).
    Используем при смене пароля и удалении аккаунта."""

    for name in (settings.ACCESS_COOKIE_NAME, settings.REFRESH_COOKIE_NAME):
        resp.delete_cookie(name, domain=settings.COOKIE_DOMAIN, path=settings.COOKIE_PATH, samesite=settings.COOKIE_SAMESITE)
