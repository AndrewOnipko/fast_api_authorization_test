from __future__ import annotations
import os
from datetime import timedelta, datetime, timezone
from pydantic import BaseModel


class Settings(BaseModel):
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/auth")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me")
    JWT_ALG: str = os.getenv("JWT_ALG", "HS256")
    ACCESS_TOKEN_TTL: int = int(os.getenv("ACCESS_TOKEN_TTL", "900"))        # 15 минут
    REFRESH_TOKEN_TTL: int = int(os.getenv("REFRESH_TOKEN_TTL", "604800"))   # 7 дней например

    CORS_ALLOW_ORIGINS: list[str] = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:5173").split(",")]
    ALLOWED_HOSTS: list[str] = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")]

    ACCESS_COOKIE_NAME: str = os.getenv("ACCESS_COOKIE_NAME", "access_token")
    REFRESH_COOKIE_NAME: str = os.getenv("REFRESH_COOKIE_NAME", "refresh_token")
    COOKIE_DOMAIN: str | None = os.getenv("COOKIE_DOMAIN")  
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax")  
    COOKIE_PATH: str = os.getenv("COOKIE_PATH", "/")

    def access_delta(self) -> timedelta:
        return timedelta(seconds=self.ACCESS_TOKEN_TTL)

    def refresh_delta(self) -> timedelta:
        return timedelta(seconds=self.REFRESH_TOKEN_TTL)

    def cookie_expiry(self, seconds: int) -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=seconds)


settings = Settings()
