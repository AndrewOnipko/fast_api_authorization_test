from fastapi import status
from app.models.auth import AuthOk

class AuthDocs:
    register = {
        "summary": "Register a new user",
        "description": (
            "Создаёт пользователя по email и паролю. "
            "Устанавливает JWT (access/refresh) в HttpOnly cookies.\n\n"
            "Access живёт ~ACCESS_TOKEN_TTL (по умолчанию 15 мин), "
            "Refresh — ~REFRESH_TOKEN_TTL (по умолчанию 7 дней)."
        ),
        "status_code": status.HTTP_201_CREATED,
        "response_model": AuthOk,
        "responses": {
            201: {"description": "User created. Cookies set."},
            409: {"description": "Email already registered"},
            422: {"description": "Validation error"},
        },
    }

    login = {
        "summary": "Login with email & password",
        "description": (
            "Аутентификация по email+password. "
            "Устанавливает новую пару JWT (access/refresh) в HttpOnly cookies."
        ),
        "response_model": AuthOk,
        "responses": {
            200: {"description": "Authenticated. Cookies set."},
            401: {"description": "Invalid credentials"},
            422: {"description": "Validation error"},
        },
    }

    refresh = {
        "summary": "Rotate tokens using refresh",
        "description": (
            "Ротация токенов по refresh (из тела или cookie). "
            "Старый refresh помечается revoked, новые токены ставятся в cookies."
        ),
        "response_model": AuthOk,
        "responses": {
            200: {"description": "Rotated. Cookies set."},
            400: {"description": "Missing/invalid token type"},
            401: {"description": "Refresh invalid/revoked/expired"},
        },
    }

    logout = {
        "summary": "Logout (revoke refresh and clear cookies)",
        "description": (
            "Отзывает refresh-токен (из тела или из cookie) и очищает HttpOnly cookies. "
            "Идемпотентно."
        ),
        "responses": {
            200: {"description": "Logged out"},
            400: {"description": "Wrong token type"},
        },
    }
