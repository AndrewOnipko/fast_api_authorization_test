from app.models.users import UserOut

class UsersDocs:
    me = {
        "summary": "Get current user (whoami)",
        "description": (
            "Возвращает данные текущего пользователя по access-токену. "
            "Токен можно передать в заголовке `Authorization: Bearer <token>`, "
            "или он будет прочитан из HttpOnly cookie (access_token)."
        ),
        "response_model": UserOut,
        "responses": {
            200: {"description": "OK"},
            401: {"description": "Missing/invalid token or inactive user"},
        },
    }


    update_password = {
        "summary": "Update password (self)",
        "description": (
            "Обновляет пароль текущего пользователя. "
            "Нужно передать свой email, текущий пароль и новый пароль. "
            "Работает только для своего аккаунта (email должен совпадать с авторизованным пользователем). "
            "После смены пароля все refresh-токены пользователя отзываются и cookies очищаются."
        ),
        "responses": {
            200: {"description": "Password updated, user logged out everywhere"},
            400: {"description": "New password invalid"},
            401: {"description": "Current password is wrong"},
            403: {"description": "Email is not your own"},
            404: {"description": "User not found"},
        },
    }


    delete_me = {
        "summary": "Delete current account",
        "description": (
            "Удаляет текущий аккаунт. Тело запроса не требуется. "
            "Разрешено удалять только самого себя (по access-токену). "
            "Все refresh-токены пользователя отзываются, cookies очищаются."
        ),
        "responses": {
            200: {"description": "User deleted"},
            404: {"description": "User not found"},
        },
    }