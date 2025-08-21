from __future__ import annotations
from typing import Any, Optional, Union
from uuid import UUID
from app.core.logger import get_logger, simple_logger

import asyncpg


class UsersRepo:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.logger = get_logger()


    @simple_logger
    async def get_by_id(self, user_id: str | UUID) -> Optional[dict[str, Any]]:
        """Возвращает пользователя по ID или None, если не нашёл.
        Поля: id, email, password_hash, is_active, is_superuser, created_at"""

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id, email, password_hash, is_active, is_superuser, created_at FROM users WHERE id = $1", user_id)
            return dict(row) if row else None


    @simple_logger
    async def get_by_email(self, email: str) -> Optional[dict[str, Any]]:
        """Возвращает пользователя по email или None."""

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id, email, password_hash, is_active, is_superuser, created_at FROM users WHERE email = $1", email)
            return dict(row) if row else None


    @simple_logger
    async def create(self, email: str, password_hash: str) -> dict[str, Any]:
        """Создаёт пользователя и возвращает созданную строку. Уникальность email обеспечивается уникальным индексом в БД."""

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO users (email, password_hash)
                VALUES ($1, $2)
                RETURNING id, email, password_hash, is_active, is_superuser, created_at""",
                email,
                password_hash)
            return dict(row)
        
    
    @simple_logger
    async def update_password_by_id(self, user_id: Union[str, UUID], new_password_hash: str) -> bool:
        """Обновляет пароль пользователя по ID. Возвращает True если что-то обновилось."""

        async with self.pool.acquire() as conn:
            res = await conn.execute(
                "UPDATE users SET password_hash = $2 WHERE id = $1",
                user_id,
                new_password_hash
            )
            return res.split(" ")[0] == "UPDATE" and int(res.split(" ")[1]) > 0


    @simple_logger
    async def delete_by_email(self, email: str) -> bool:
        """Удаляет пользователя по email. Возвращает True, если пользователь был удалён."""
        async with self.pool.acquire() as conn:
            res = await conn.execute("DELETE FROM users WHERE email = $1", email)
            return res.split(" ")[0] == "DELETE" and int(res.split(" ")[1]) > 0