from __future__ import annotations
import logging
import os
import inspect
import time
from functools import wraps
from typing import Any, Callable

_LOGGER_NAME = "auth"

PRIVATE_KEYWORDS = {
    "api_key", "bearer", "authorization", "headers", "analytics",
    "client_id", "client_secret", "grant_type", "token_type",
    "expires_in", "access_token", "refresh_token", "token",
    "password", "pma_username", "pma_password",
}


def setup_logging() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        level_name = os.getenv("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)
        logger.setLevel(level)

        fmt = "%(asctime)s %(levelname)s %(name)s :: %(message)s"
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        logger.propagate = False
    return logger


def get_logger() -> logging.Logger:
    return setup_logging()


def _mask_private_data(data: Any) -> Any:
    try:
        if isinstance(data, dict):
            out = {}
            for k, v in data.items():
                k_str = str(k)
                if any(kw in k_str.lower() for kw in PRIVATE_KEYWORDS):
                    out[k_str] = "***hidden***"
                else:
                    out[k_str] = _mask_private_data(v)
            return out
        elif isinstance(data, (list, tuple)):
            seq = [_mask_private_data(x) for x in data]
            return type(data)(seq) if isinstance(data, tuple) else seq
        elif isinstance(data, str):
            if any(kw in data.lower() for kw in PRIVATE_KEYWORDS):
                return "***hidden***"
            return data if len(data) <= 500 else data[:500] + "...(trimmed)"
        else:
            return data
    except Exception:
        return "***masked***"


def simple_logger(func: Callable) -> Callable:
    is_async = inspect.iscoroutinefunction(func)

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        logger = None
        if args and hasattr(args[0], "logger"):
            logger = getattr(args[0], "logger")
        if logger is None:
            logger = get_logger()

        masked_args = _mask_private_data(args)
        masked_kwargs = _mask_private_data(kwargs)

        start = time.perf_counter()
        logger.debug(f"Запуск {func.__name__}() args={masked_args}, kwargs={masked_kwargs}")
        try:
            result = await func(*args, **kwargs)  
            dur_ms = int((time.perf_counter() - start) * 1000)
            logger.debug(f"Готово {func.__name__}() за {dur_ms} ms")
            return result
        except Exception as e:
            logger.error(f"Ошибка в {func.__name__}(): {e}")
            raise

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        logger = None
        if args and hasattr(args[0], "logger"):
            logger = getattr(args[0], "logger")
        if logger is None:
            logger = get_logger()

        masked_args = _mask_private_data(args)
        masked_kwargs = _mask_private_data(kwargs)

        start = time.perf_counter()
        logger.debug(f"Запуск {func.__name__}() args={masked_args}, kwargs={masked_kwargs}")
        try:
            result = func(*args, **kwargs)
            dur_ms = int((time.perf_counter() - start) * 1000)
            logger.debug(f"Готово {func.__name__}() за {dur_ms} ms")
            return result
        except Exception as e:
            logger.error(f"Ошибка в {func.__name__}(): {e}")
            raise

    return async_wrapper if is_async else sync_wrapper
