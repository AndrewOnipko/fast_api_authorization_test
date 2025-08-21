# Auth Service (FastAPI + PostgreSQL + Docker)

Простой сервис авторизации: регистрация, логин, ротация refresh, whoami, смена пароля, удаление аккаунта.  
Python 3.12, FastAPI, PostgreSQL (asyncpg), Docker.

## Фичи
- Регистрация/логин по email+паролю, хеш **Argon2**
- **JWT**: короткий access и длинный refresh
- **Ротация refresh** (старый помечаем revoked, новый выдаём)
- **HttpOnly cookies** для access/refresh (+ можно работать по Bearer)
- CORS allowlist, TrustedHost, доп. проверка Origin
- Простые логи + `X-Request-ID` + централизованная обработка ошибок
- SQL-миграции накатываются автоматически при старте

## Быстрый старт

1) Создать файл `.env` (пример):

```env
# Postgres
POSTGRES_DB=auth
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

# App
DATABASE_URL=postgresql://postgres:postgres@db:5432/auth
JWT_SECRET=please-change-me
JWT_ALG=HS256
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=604800

# CORS / Hosts
CORS_ALLOW_ORIGINS=http://localhost:5173,http://localhost:8000
ALLOWED_HOSTS=localhost,127.0.0.1

# Cookies
ACCESS_COOKIE_NAME=access_token
REFRESH_COOKIE_NAME=refresh_token
COOKIE_SECURE=false
COOKIE_SAMESITE=lax
COOKIE_PATH=/

# Logs
LOG_LEVEL=INFO
```

2) Запуск:

```bash
docker compose up --build
# API    -> http://localhost:8000
# Swagger -> http://localhost:8000/docs
```

Миграции из app/migrations/*.sql применяются автоматически на старте.

## Стек

- Python 3.12, FastAPI

- PostgreSQL, asyncpg (без ORM)

- JWT (PyJWT), Argon2 (passlib)

- Docker / docker-compose

## Структура

```text
app/
  api/
    auth_router.py
    users_router.py
    deps.py
  core/
    config.py
    db.py
    logger.py
    security.py
  docs/
    auth_docs.py
    users_docs.py
  models/
    auth.py
    user.py
  repositories/
    users.py
    refresh_tokens.py
  migrations/
    0001_init.sql
```

## Эндпоинты:

# Auth

- POST /auth/register — создать пользователя, выдать access/refresh (+ куки)

- POST /auth/login — вход, выдать access/refresh (+ куки)

- POST /auth/refresh — ротация по refresh (из тела или из cookie)

- POST /auth/logout — revoke refresh + очистить cookies

# Users

- GET /users/me — текущий пользователь

- PATCH /users/me/password — смена пароля (нужны email, current_password, new_password)

- DELETE /users/me — удалить текущий аккаунт


## Безопасность

- Пароли — Argon2

- JWT подписан JWT_SECRET (HS256)

- Refresh хранится по jti в БД → можно ревокнуть, реализована ротация

- HttpOnly cookies с SameSite=lax (для локалки)

- CORS: только из CORS_ALLOW_ORIGINS; плюс проверка Origin; TrustedHost по ALLOWED_HOSTS