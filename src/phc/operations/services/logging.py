"""구조화 로깅 (S09) — L-06 `CorrelationIdProvider` · L-07 `RedactionProcessor`.

이중 방어:
    1차(정적) — 로그 함수가 ``Redactable`` 만 받도록 하여 mypy 가 잡음
    2차(런타임) — ``RedactionProcessor`` 가 **동적 딕셔너리 우회를 차단**

Phase 1 에서 확인했듯 정적 검사만으로는 부족합니다. ``logger.info("x", **d)``
처럼 딕셔너리를 펼치면 타입 검사가 통과하고, 그 안에 ``SecretStr`` 이 들어
있어도 걸리지 않습니다. 이 프로세서가 그 경로를 막습니다 (NFR-04, BR-AU-02).

개발 환경에서는 **예외를 던져 즉시 발견**하게 하고, 운영 환경에서는 값을
대체한 뒤 경고를 남깁니다. 운영 중에 로깅 때문에 요청이 죽는 것은
그 자체로 사고이기 때문입니다.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Final

import structlog

from phc.shared import PasswordHash, SecretStr, SessionToken, SupportsRedactedRepr

__all__ = [
    "REDACTED",
    "CorrelationIdProvider",
    "RedactionError",
    "RedactionProcessor",
    "configure_logging",
    "get_logger",
]

REDACTED: Final = "<redacted>"

#: 타입만으로는 판단할 수 없는 경우를 위한 키 이름 차단 목록.
#: 문자열로 넘어온 비밀번호처럼 타입 방어를 빠져나간 값을 잡습니다.
_FORBIDDEN_KEY_PARTS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "session_id",
        "temp_password",
    }
)

#: 로그에 담기면 안 되는 타입.
_FORBIDDEN_TYPES: Final = (SecretStr, PasswordHash, SessionToken)

_correlation_id: ContextVar[str | None] = ContextVar("phc_correlation_id", default=None)


class RedactionError(RuntimeError):
    """개발 환경에서 민감값이 로그로 향할 때 발생.

    운영 환경에서는 발생하지 않고 값이 대체됩니다.
    """


class CorrelationIdProvider:
    """요청·작업 단위 상관관계 ID (L-06).

    웹 요청은 진입 시 새 ID 를, 워커는 ``JobId`` 를 상관관계 ID 로 씁니다.
    두 경로의 로그를 같은 방식으로 추적할 수 있게 하기 위함입니다.
    """

    @staticmethod
    def new_id() -> str:
        return uuid.uuid4().hex[:16]

    @staticmethod
    def current() -> str | None:
        return _correlation_id.get()

    @staticmethod
    @contextmanager
    def scope(correlation_id: str | None = None) -> Iterator[str]:
        cid = correlation_id or CorrelationIdProvider.new_id()
        token = _correlation_id.set(cid)
        try:
            yield cid
        finally:
            _correlation_id.reset(token)


def _bind_correlation_id(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    cid = _correlation_id.get()
    if cid is not None:
        event_dict.setdefault("correlation_id", cid)
    return event_dict


class RedactionProcessor:
    """⭐ 민감값이 로그로 나가는 것을 런타임에서 차단 (L-07).

    검사 순서:
        1. 값의 **타입** 이 금지 타입인가
        2. 값이 ``Redactable`` 을 만족하는가 -> ``__redacted_repr__`` 사용
        3. **키 이름** 에 금지 문자열이 포함되는가

    3번이 필요한 이유: ``logger.info("login", password=raw_str)`` 처럼 평문
    ``str`` 로 넘기면 타입 검사를 빠져나갑니다. 키 이름으로 한 겹 더 막습니다.
    """

    def __init__(self, *, strict: bool) -> None:
        #: 개발 환경에서는 True. 즉시 예외를 던져 문제를 드러냅니다.
        self.strict = strict

    def __call__(
        self, _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        for key, value in list(event_dict.items()):
            replacement = self._inspect(key, value)
            if replacement is not None:
                event_dict[key] = replacement
        return event_dict

    def _inspect(self, key: str, value: Any) -> str | None:
        """대체가 필요하면 대체 문자열을, 아니면 None 을 반환."""
        if isinstance(value, _FORBIDDEN_TYPES):
            self._violation(key, type(value).__name__)
            return REDACTED

        lowered = key.lower()
        if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
            self._violation(key, "forbidden key name")
            return REDACTED

        if isinstance(value, SupportsRedactedRepr):
            return value.__redacted_repr__()

        return None

    def _violation(self, key: str, reason: str) -> None:
        if self.strict:
            raise RedactionError(
                f"민감값이 로그로 전달되었습니다: key={key!r} ({reason}). "
                f"Redactable 타입만 로그에 담을 수 있습니다 (NFR-04, BR-AU-02)."
            )


def configure_logging(*, env: str = "prod", level: int = logging.INFO) -> None:
    """structlog 를 구성한다.

    Args:
        env: ``dev`` 이면 사람이 읽는 포맷 + 민감값 발견 시 즉시 예외.
            ``prod`` 이면 JSON Lines + 값 대체 후 경고.
    """
    is_dev = env == "dev"

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        _bind_correlation_id,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        RedactionProcessor(strict=is_dev),
        structlog.processors.StackInfoRenderer(),
    ]

    if is_dev:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))
    else:
        processors.append(structlog.processors.format_exc_info)
        processors.append(structlog.processors.JSONRenderer(ensure_ascii=False))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
