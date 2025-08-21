from __future__ import annotations
import pathlib
import asyncpg
from fastapi import FastAPI
from app.core.config import settings

POOL_KEY = "db_pool"

async def create_pool(app: FastAPI) -> None:
    """Создаем пул подключений"""
    pool = await asyncpg.create_pool(dsn=settings.DATABASE_URL, min_size=1, max_size=10)
    app.state.__setattr__(POOL_KEY, pool)


def get_pool(app: FastAPI) -> asyncpg.pool.Pool:
    """Получаем пул подключений"""
    return getattr(app.state, POOL_KEY)


async def close_pool(app: FastAPI) -> None:
    """Закрываем пул подключений"""
    pool = get_pool(app)
    await pool.close()


async def run_migrations(app: FastAPI) -> None:
    """Простая система миграций:
    - создаём служебную таблицу schema_migrations (если её нет)
    - применяем все .sql файлы из папки migrations по алфавиту
    - записываем имя применённого файла, чтобы не накатывать его снова"""

    pool = get_pool(app)
    migrations_dir = pathlib.Path(__file__).resolve().parents[1] / "migrations"
    files = sorted([p for p in migrations_dir.glob("*.sql")])

    async with pool.acquire() as conn:
        await conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                           id SERIAL PRIMARY KEY,
                           filename TEXT UNIQUE NOT NULL,
                           applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                           );""")

        applied = {r[0] for r in await conn.fetch("SELECT filename FROM schema_migrations")}
        for file in files:
            if file.name in applied:
                continue
            sql = file.read_text(encoding="utf-8")
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute("INSERT INTO schema_migrations(filename) VALUES($1)", file.name)