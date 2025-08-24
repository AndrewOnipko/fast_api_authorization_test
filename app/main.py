from contextlib import asynccontextmanager
from uuid import uuid4
import time

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.db import create_pool, close_pool, run_migrations
from app.core.config import settings
from app.api.auth_router import router as auth_router
from app.api.users_router import router as users_router
from app.core.logger import get_logger 

log = get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_pool(app)
    await run_migrations(app)
    yield
    await close_pool(app)


app = FastAPI(title="Auth Service", version="1.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
    )


app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)


@app.middleware("http")
async def add_request_id_and_access_log(request: Request, call_next):
    """Для каждого запроса:
    - генерим request_id (возвращаем в X-Request-ID)
    - меряем время выполнения
    - ловим неожиданные исключения → отдаём 500 + пишем лог"""
    request_id = str(uuid4())
    request.state.request_id = request_id

    start = time.perf_counter()
    try:
        response = await call_next(request)
    except HTTPException:
        raise
    except Exception:
        log.exception(
            "unhandled exception",
            extra={"request_id": request_id, "method": request.method, "path": request.url.path}
            )
        return JSONResponse(
            {"detail": "Internal Server Error", "request_id": request_id},
            status_code=500
            )

    dur_ms = int((time.perf_counter() - start) * 1000)
    log.info(
        "request done",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": dur_ms
            }
        )
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def enforce_origin_allowlist(request: Request, call_next):
    """Если пришёл браузерный запрос с Origin не из allowlist — режем 403. (Preflight OPTIONS не блокируем.)"""

    origin = request.headers.get("Origin")
    if origin and origin not in settings.CORS_ALLOW_ORIGINS and request.method != "OPTIONS":
        return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
    return await call_next(request)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Логируем HTTP-исключения (401/403/409 и т.д.) как warning, и отдаём аккуратный JSON."""

    req_id = getattr(request.state, "request_id", "-")
    detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
    log.warning(
        "http_error",
        extra={
            "request_id": req_id,
            "method": request.method,
            "path": request.url.path,
            "status": exc.status_code,
            "detail": detail
            }
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Логируем ошибки валидации (422), чтобы понимать, что именно не прошло."""

    req_id = getattr(request.state, "request_id", "-")
    log.warning(
        "validation_error",
        extra={
            "request_id": req_id,
            "method": request.method,
            "path": request.url.path,
            "errors": exc.errors()
            }
        )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router, prefix="/users", tags=["users"])


@app.get("/health")
async def health():
    return {"status": "ok"}
