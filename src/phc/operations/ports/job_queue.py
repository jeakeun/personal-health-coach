"""작업 큐 포트와 핸들러 레지스트리.

⭐ **DIP 로 순환 의존을 해소하는 지점입니다.**

    ``JobWorker``(operations)가 취입 작업을 실행하려면 ``IngestionCoordinator``
    (healthdata)를 호출해야 하고, ``IngestionService``(healthdata)는
    ``JobQueuePort``(operations)에 작업을 등록해야 합니다 — 순환입니다.

    해소: ``operations`` 가 ``JobHandler`` **포트를 정의**하고,
    ``healthdata`` 가 ``IngestionJobHandler`` 로 **구현·등록**합니다.
    ``operations`` 는 자기 포트만 알고 ``healthdata`` 를 모릅니다.
    계약 C1(계층 순서)이 이를 기계적으로 확인합니다.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol

from phc.operations.domain.job import Job, JobId, JobKind, JobSpec, WorkerId
from phc.shared import DomainError, OwnerScope

__all__ = ["JobHandler", "JobHandlerRegistry", "JobQueuePort", "ProgressCallback"]

#: 진행률 보고 콜백. 워커가 heartbeat 갱신과 함께 호출합니다.
ProgressCallback = Callable[[int], None]


class JobHandler(Protocol):
    """작업 종류별 실행기.

    구현체는 해당 도메인 모듈에 있습니다 (1B 의 취입 핸들러 등).
    """

    @property
    def kind(self) -> JobKind:
        """이 핸들러가 처리하는 작업 종류."""
        ...

    def execute(self, job: Job, scope: OwnerScope, progress: ProgressCallback) -> str | None:
        """작업을 실행하고 결과 참조를 반환한다.

        Args:
            job: 실행할 작업.
            scope: ⭐ 워커가 ``job.owner_id`` 로부터 재구성한 소유 범위.
                핸들러는 이 스코프 밖의 데이터에 접근할 수 없습니다 (BR-JQ-07).
            progress: 진행률 보고 콜백 (0~100).

        Raises:
            RetryableJobError: 일시적 실패. 재시도 대상입니다.
            DomainError: 그 외 실패는 재시도 불가로 간주합니다 (BR-JQ-06).
        """
        ...


class RetryableJobError(DomainError):
    """재시도하면 성공할 수 있는 실패 (일시적 I/O 오류 등).

    이 예외가 **아닌** 실패는 재시도하지 않습니다. 형식 오류나 검증 실패는
    같은 입력으로 다시 시도해도 결과가 같기 때문입니다.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("job_retryable_failure", "작업을 다시 시도합니다.", detail=reason)


class JobHandlerRegistry:
    """작업 종류 -> 핸들러 매핑.

    조립 루트에서 핸들러를 등록합니다. 등록되지 않은 종류의 작업은
    **재시도 불가 실패**로 처리합니다 — 재시도해도 핸들러가 생기지 않습니다.
    """

    def __init__(self) -> None:
        self._handlers: dict[JobKind, JobHandler] = {}

    def register(self, handler: JobHandler) -> None:
        if handler.kind in self._handlers:
            raise ValueError(f"이미 등록된 작업 종류입니다: {handler.kind.value}")
        self._handlers[handler.kind] = handler

    def get(self, kind: JobKind) -> JobHandler | None:
        return self._handlers.get(kind)

    def registered_kinds(self) -> frozenset[JobKind]:
        return frozenset(self._handlers)


class JobQueuePort(Protocol):
    """DB 작업 테이블 기반 큐 (D5=A).

    향후 SQS 등으로 교체할 때 이 포트 뒤의 어댑터만 바꿉니다.
    """

    def enqueue(self, spec: JobSpec, *, now: datetime) -> Job:
        """작업을 등록하고 즉시 반환한다."""
        ...

    def claim(self, worker: WorkerId, *, now: datetime) -> Job | None:
        """실행 가능한 작업을 하나 점유한다.

        조건: ``state == PENDING`` 이고 ``next_attempt_at <= now`` (BR-JQ-02).
        동시에 두 워커가 같은 작업을 점유하지 않아야 합니다.
        """
        ...

    def save(self, job: Job) -> None:
        """전이된 작업 상태를 저장한다."""
        ...

    def get(self, job_id: JobId) -> Job | None: ...

    def find_stale(self, *, now: datetime, timeout: timedelta) -> list[Job]:
        """heartbeat 가 끊긴 실행 중 작업을 찾는다 (회수 대상)."""
        ...

    def count_by_state(self) -> dict[str, int]:
        """상태별 작업 수. 메트릭·대시보드용."""
        ...
