"""작업 워커와 회수기 (S12) — L-12 `JobReaper` · L-13 연계.

D5=A: 동일 프로세스의 백그라운드 스레드로 실행합니다. 별도 프로세스를 두면
사용자가 두 개를 띄워야 하고, 로컬 데스크톱 앱의 "실행하면 그냥 된다" 가
깨집니다.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Final

from phc.operations.domain.job import Job, JobState, WorkerId
from phc.operations.ports.audit import AuditTrailPort
from phc.operations.ports.job_queue import (
    JobHandlerRegistry,
    JobQueuePort,
    RetryableJobError,
)
from phc.operations.services.logging import CorrelationIdProvider, get_logger
from phc.shared import AuthContext, ClockPort, DomainError, OwnerScope, Role, UserId

__all__ = ["DEFAULT_HEARTBEAT_TIMEOUT", "JobReaper", "JobWorker"]

_log = get_logger(__name__)

#: heartbeat 가 이 시간 이상 갱신되지 않으면 워커가 죽은 것으로 봅니다 (F8=A).
DEFAULT_HEARTBEAT_TIMEOUT: Final = timedelta(minutes=5)


def _reconstruct_scope(owner_id: UserId) -> OwnerScope:
    """⭐ 작업 소유자의 스코프를 재구성한다 — **이 코드베이스의 유일한 특권 지점**.

    워커에는 요청 컨텍스트가 없으므로 ``AuthContext`` 를 직접 만듭니다.
    이것은 임의 사용자의 스코프를 만들 수 있다는 뜻이므로, 경계 B 의 관점에서
    설명이 필요합니다.

    **안전한 이유**: 작업은 ``JobSpec.for_scope(scope)`` 로 등록되며, 그
    ``scope`` 는 이미 인가를 통과한 것입니다. 즉 ``job.owner_id`` 는 "누군가가
    이미 인가받은 소유자" 이지 임의 값이 아닙니다.

    **그래서 지켜야 할 것**: ``JobSpec`` 을 ``owner_id`` 직접 지정으로 만들면
    이 전제가 깨집니다. 작업을 등록하는 모든 코드는 ``for_scope`` 를 써야 합니다.

    역할은 ``USER`` 로 고정합니다. 배경 작업이 관리자 권한을 갖는 경로를
    만들지 않기 위함입니다.
    """
    return OwnerScope.for_subject(AuthContext(subject_id=owner_id, role=Role.USER))


class JobWorker:
    """큐에서 작업을 꺼내 실행한다."""

    def __init__(
        self,
        *,
        queue: JobQueuePort,
        registry: JobHandlerRegistry,
        clock: ClockPort,
        worker_id: WorkerId,
        audit: AuditTrailPort | None = None,
    ) -> None:
        self._queue = queue
        self._registry = registry
        self._clock = clock
        self._worker_id = worker_id
        self._audit = audit
        self._stop = threading.Event()

    # -- 단일 실행 ----------------------------------------------------------
    def run_once(self) -> bool:
        """작업 하나를 처리한다. 처리할 작업이 없으면 ``False``."""
        now = self._clock.now()
        job = self._queue.claim(self._worker_id, now=now)
        if job is None:
            return False

        # 작업 ID 를 상관관계 ID 로 사용 — 웹 요청과 같은 방식으로 추적 가능
        with CorrelationIdProvider.scope(job.id.value):
            self._execute(job)
        return True

    def _execute(self, job: Job) -> None:
        handler = self._registry.get(job.kind)
        if handler is None:
            # 재시도해도 핸들러가 생기지 않으므로 재시도 불가로 처리
            self._fail(job, reason=f"등록되지 않은 작업 종류: {job.kind.value}", retryable=False)
            return

        scope = _reconstruct_scope(job.owner_id)

        def report_progress(percent: int) -> None:
            current = self._queue.get(job.id)
            if current is not None and current.state is JobState.RUNNING:
                self._queue.save(current.heartbeat(now=self._clock.now(), progress_percent=percent))

        try:
            result_ref = handler.execute(job, scope, report_progress)
        except RetryableJobError as exc:
            self._fail(job, reason=exc.detail or exc.code, retryable=True)
        except DomainError as exc:
            self._fail(job, reason=exc.code, retryable=False)
        except Exception as exc:  # 광범위 포착 사유: 워커 스레드가 죽지 않게 최종 방어
            _log.error("job.unexpected_error", job_id=job.id, error_type=type(exc).__name__)
            self._fail(job, reason=f"unexpected:{type(exc).__name__}", retryable=True)
        else:
            self._succeed(job, result_ref)

    def _succeed(self, job: Job, result_ref: str | None) -> None:
        current = self._queue.get(job.id) or job
        self._queue.save(current.complete(now=self._clock.now(), result_ref=result_ref))
        _log.info("job.succeeded", job_id=job.id, kind=job.kind)

    def _fail(self, job: Job, *, reason: str, retryable: bool) -> None:
        current = self._queue.get(job.id) or job
        failed = current.fail(now=self._clock.now(), reason=reason, retryable=retryable)
        self._queue.save(failed)
        _log.warning(
            "job.failed",
            job_id=job.id,
            kind=job.kind,
            attempts=failed.attempts,
            will_retry=failed.state is JobState.PENDING,
        )

    # -- 스레드 실행 --------------------------------------------------------
    def run_forever(self, *, idle_sleep: float = 1.0) -> None:
        """중단 신호가 올 때까지 반복 처리한다."""
        while not self._stop.is_set():
            try:
                worked = self.run_once()
            except Exception as exc:  # 광범위 포착 사유: 루프 자체가 죽으면 큐가 멈춤
                _log.error("worker.loop_error", error_type=type(exc).__name__)
                worked = False
            if not worked:
                self._stop.wait(idle_sleep)

    def request_stop(self) -> None:
        """신규 claim 을 중단한다 (L-13 우아한 종료 1단계)."""
        self._stop.set()

    @property
    def is_stopping(self) -> bool:
        return self._stop.is_set()


class JobReaper:
    """죽은 워커의 작업을 회수한다 (L-12, BR-JQ-04).

    ⭐ 회수 시 ``attempts`` 를 **증가시키지 않습니다.** 워커 프로세스가 죽은
    것은 작업 내용의 실패가 아닙니다. 여기서 재시도 횟수를 소모시키면 앱
    재기동이 반복될 때 정상 작업이 FAILED 로 떨어집니다.
    """

    def __init__(
        self,
        *,
        queue: JobQueuePort,
        clock: ClockPort,
        timeout: timedelta = DEFAULT_HEARTBEAT_TIMEOUT,
    ) -> None:
        self._queue = queue
        self._clock = clock
        self._timeout = timeout

    def reap_stale(self) -> int:
        """회수한 작업 수를 반환한다.

        감사 기록 대상이 아닙니다 — 회수는 보안 사건이 아니라 정상적인 복구
        동작입니다. 감사 이벤트 목록(domain-entities.md §3)을 임의로 늘리지
        않고 구조화 로그로 남깁니다.
        """
        now: datetime = self._clock.now()
        stale = self._queue.find_stale(now=now, timeout=self._timeout)

        for job in stale:
            self._queue.save(job.reap(now=now))
            _log.warning(
                "job.reaped",
                job_id=job.id,
                kind=job.kind,
                attempts=job.attempts,
                stale_since=job.heartbeat_at.isoformat() if job.heartbeat_at else None,
            )

        return len(stale)
