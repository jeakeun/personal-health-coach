"""전역 오류 처리와 우아한 종료 (S15) — L-05 · L-13.

⭐ 작업을 억지로 완료시키지 않습니다. ``JobReaper`` 가 회수하므로
   **중단이 곧 유실이 아닙니다** (BR-JQ-10).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from phc.operations.services.logging import CorrelationIdProvider, get_logger
from phc.operations.services.metrics import MetricName, MetricsRegistry
from phc.shared import DomainError

__all__ = ["GlobalErrorHandler", "SafeResponse", "ShutdownCoordinator"]

_log = get_logger(__name__)

WEB_DRAIN_TIMEOUT: Final = timedelta(seconds=30)
WORKER_DRAIN_TIMEOUT: Final = timedelta(seconds=60)


@dataclass(frozen=True, slots=True)
class SafeResponse:
    """사용자에게 반환할 안전한 오류 응답.

    ⚠ 스택 트레이스 · 내부 경로 · 프레임워크 버전을 담지 않습니다 (NFR-1A-26).
    ``correlation_id`` 는 담습니다 — 사용자가 문의 시 인용할 수 있고,
    그 자체로는 내부 구조를 드러내지 않습니다.
    """

    status_code: int
    code: str
    message: str
    correlation_id: str | None = None


class GlobalErrorHandler:
    """미처리 예외를 안전한 응답으로 변환한다 (L-05, BR-ER-04)."""

    GENERIC_MESSAGE: Final = "요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요."

    def __init__(self, *, metrics: MetricsRegistry) -> None:
        self._metrics = metrics

    def handle(self, exc: BaseException) -> SafeResponse:
        cid = CorrelationIdProvider.current()

        if isinstance(exc, DomainError):
            # 도메인 오류는 사용자에게 보여도 되는 문구를 이미 갖고 있습니다.
            _log.warning(
                "request.domain_error",
                error_code=exc.code,
                error_detail=exc.detail,
            )
            return SafeResponse(
                status_code=self._status_for(exc),
                code=exc.code,
                message=exc.safe_message,
                correlation_id=cid,
            )

        # 예상하지 못한 예외 — 내부 정보를 절대 밖으로 내지 않습니다.
        self._metrics.increment(MetricName.ERROR_UNHANDLED)
        _log.error(
            "request.unhandled_error",
            error_type=type(exc).__name__,
            exc_info=exc,
        )
        return SafeResponse(
            status_code=500,
            code="internal_error",
            message=self.GENERIC_MESSAGE,
            correlation_id=cid,
        )

    @staticmethod
    def _status_for(exc: DomainError) -> int:
        return {
            "authz_denied": 403,
            "validation_failed": 400,
            "undetermined": 503,
            "startup_failed": 503,
        }.get(exc.code, 400)


class ShutdownCoordinator:
    """기동 순서의 역순으로 정리한다 (L-13).

    순서:
        1. 웹 서버 — 신규 요청 수락 중단, 진행 중 완료 대기 (최대 30초)
        2. 워커 — 신규 claim 중단, 진행 중 완료 대기 (최대 60초)
        3. 초과 시 heartbeat 중단 후 종료 → JobReaper 가 다음 기동에서 회수
        4. DB 커넥션 정리
    """

    def __init__(self) -> None:
        self._web_stop: Callable[[], None] | None = None
        self._worker_stops: list[Callable[[], None]] = []
        self._worker_threads: list[threading.Thread] = []
        self._db_close: Callable[[], None] | None = None

    def register_web_stop(self, stop: Callable[[], None]) -> None:
        self._web_stop = stop

    def register_worker(self, stop: Callable[[], None], thread: threading.Thread) -> None:
        self._worker_stops.append(stop)
        self._worker_threads.append(thread)

    def register_db_close(self, close: Callable[[], None]) -> None:
        self._db_close = close

    def shutdown(self) -> None:
        _log.info("shutdown.started")

        if self._web_stop is not None:
            self._safely("web_stop", self._web_stop)

        for stop in self._worker_stops:
            self._safely("worker_stop", stop)

        deadline = WORKER_DRAIN_TIMEOUT.total_seconds()
        for thread in self._worker_threads:
            # 시작된 적 없는 스레드를 join 하면 RuntimeError 가 나서 종료 절차
            # 전체가 멈춥니다. 기동 도중 실패해 워커가 시작되지 못한 경우가
            # 실제로 그 상황입니다 — 정리해야 할 때 정리가 죽습니다.
            if thread.ident is None:
                continue
            thread.join(timeout=deadline)
            if thread.is_alive():
                # 억지로 죽이지 않습니다. heartbeat 가 멈추면 5분 후 회수됩니다.
                _log.warning("shutdown.worker_still_running", thread=thread.name)

        if self._db_close is not None:
            self._safely("db_close", self._db_close)

        _log.info("shutdown.completed")

    @staticmethod
    def _safely(step: str, action: Callable[[], None]) -> None:
        try:
            action()
        except Exception as exc:  # 광범위 포착 사유: 종료 중 예외가 나머지 정리를 막지 않게
            _log.error("shutdown.step_failed", step=step, error_type=type(exc).__name__)
