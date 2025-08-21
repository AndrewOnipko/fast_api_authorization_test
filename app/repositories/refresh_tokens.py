from __future__ import annotations
from typing import Any, Optional
from uuid import UUID
import asyncpg
from app.core.logger import get_logger, simple_logger

class RefreshTokensRepo:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.logger = get_logger()


    @simple_logger
    async def issue(self, user_id: UUID, jti: UUID, exp_ts: int, ip: str | None, user_agent: str | None) -> None:
        """Регистрирует выдачу нового refresh-токена. exp_ts — это время, когда токен истечёт (в unix timestamp)."""

        async with self.pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO refresh_tokens (user_id, jti, expires_at, ip, user_agent)
                VALUES ($1, $2, to_timestamp($3), $4, $5)""",
                user_id, jti, exp_ts, ip, user_agent)


    @simple_logger
    async def get_by_jti(self, jti: str | UUID) -> Optional[dict[str, Any]]:
        """Возвращает запись по jti или None, если не нашли."""

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id, user_id, jti, revoked_at, expires_at FROM refresh_tokens WHERE jti = $1", jti)
            return dict(row) if row else None


    @simple_logger
    async def revoke(self, jti: str | UUID, reason: str | None = None) -> None:
        """Отзывает refresh-токен (если ещё не отозван). 
        revoked_at проставляется текущим временем."""

        async with self.pool.acquire() as conn:
            await conn.execute(
                """UPDATE refresh_tokens
                SET revoked_at = now(), revoke_reason = COALESCE($2, revoke_reason)
                WHERE jti = $1 AND revoked_at IS NULL
                """,
                jti, reason)
            

    @simple_logger
    async def revoke_all_for_user(self, user_id: UUID, reason: str | None = None) -> None:
        """Отзывает все активные refresh токены пользователя (например, force logout со всех устройств)."""

        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE refresh_tokens SET revoked_at = now(), revoke_reason = COALESCE($2, revoke_reason) WHERE user_id = $1 AND revoked_at IS NULL",
                user_id, reason)


    @simple_logger
    async def purge_expired(self) -> int:
        """Удаляет из таблицы все refresh токены, срок которых уже истёк.
        Возвращает количество удалённых строк."""

        async with self.pool.acquire() as conn:
            res = await conn.execute("DELETE FROM refresh_tokens WHERE expires_at < now()")
            return int(res.split(" ")[1])