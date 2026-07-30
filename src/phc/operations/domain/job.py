"""작업 큐 도메인 — 상태 기계.

D5=A 로 인프로세스 작업 큐를 택했습니다. 외부 브로커 없이 DB 작업 테이블과
워커 스레드로 구성하며, 이 모듈은 그 **상태 전이 규칙**을 담습니다.

⭐ 이 상태 기계는 PBT 속성 4(PBT-06 상태 기반)의 검증 대상입니다.
   불변식이 코드가 아니라 주석으로만 존재하면 검증할 수 없으므로,
   전이를 순수 함수로 두어 임의의 연산 시퀀스에 대해 확인할 수 있게 했습니다.

불변식:
    INV-JB-01  RUNNING 이면 claimed_by 와 heartbeat_at 이 존재한다
    INV-JB-02  attempts <= max_attempts
    INV-JB-03  종료 상태(SUCCEEDED/FAILED)에서 나가는 전이가 없다
    INV-JB-04  owner_id 는 생성 후 변경되지 않는다
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from phc.shared import DomainError, OwnerScope, UserId

__all__ = [
    "BACKOFF_BASE",
    "Job",
    "JobId",
    "JobKind",
    "JobSpec",
    "JobState",
    "JobTransitionError",
    "WorkerId",
]

#: 재시도 백오프 기준. n 번째 실패 후 대기 = BACKOFF_BASE * 2^(n-1)
#: -> 1분 · 2분 · 4분 (F8=A)
BACKOFF_BASE: Final = timedelta(minutes=1)


class JobTransitionError(DomainError):
    """허용되지 않은 상태 전이 시도.

    이 예외가 발생한다는 것은 호출 순서가 잘못되었다는 뜻입니다.
    조용히 무시하면 종료된 작업이 되살아나는 등의 사고가 납니다 (INV-JB-03).
    """

    def __init__(self, current: JobState, operation: str) -> None:
        super().__init__(
            "job_invalid_transition",
            "작업 상태를 변경할 수 없습니다.",
            detail=f"state={current.value} operation={operation}",
        )


@dataclass(frozen=True, slots=True, order=True)
class JobId:
    value: str

    @classmethod
    def generate(cls) -> JobId:
        return cls(uuid.uuid4().hex)

    def __str__(self) -> str:
        return self.value

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class WorkerId:
    value: str

    def __str__(self) -> str:
        return self.value

    def __redacted_repr__(self) -> str:
        return self.value


class JobKind(StrEnum):
    """작업 종류.

    Unit 1A 에서는 백업만 있습니다. Unit 1B 에서 파일 취입(``INGEST_FILE``)이
    추가되며, ``JobHandler`` 레지스트리에 등록하는 방식이므로
    ``operations`` 모듈은 수정되지 않습니다 (DIP).
    """

    BACKUP = "backup"


class JobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        """종료 상태 여부. 종료 상태에서는 어떤 전이도 일어나지 않는다 (INV-JB-03)."""
        return self in (JobState.SUCCEEDED, JobState.FAILED)


@dataclass(frozen=True, slots=True)
class JobSpec:
    """작업 등록 요청.

    ⚠ ``payload_ref`` 는 **참조**입니다. 민감값을 직접 담지 않습니다 (BR-JQ-09).

    ⭐ ``for_scope`` 로 만드는 것을 권장합니다. ``owner_id`` 를 임의로 지정해
    등록하면, 나중에 워커가 그 소유자의 스코프를 재구성하므로 **작업 큐가
    경계 B 의 우회로가 됩니다**. ``for_scope`` 는 이미 인가된 ``OwnerScope``
    에서 소유자를 가져오므로 그 경로를 막습니다 (BR-JQ-07).
    """

    kind: JobKind
    owner_id: UserId
    payload_ref: str = ""
    max_attempts: int = 3

    @classmethod
    def for_scope(
        cls,
        kind: JobKind,
        scope: OwnerScope,
        *,
        payload_ref: str = "",
        max_attempts: int = 3,
    ) -> JobSpec:
        """이미 인가된 소유 범위로부터 작업 명세를 만든다."""
        return cls(
            kind=kind,
            owner_id=scope.owner_id,
            payload_ref=payload_ref,
            max_attempts=max_attempts,
        )


@dataclass(frozen=True, slots=True)
class Job:
    """작업 레코드.

    불변 객체이며 전이 메서드는 **새 인스턴스를 반환**합니다.
    제자리 변경을 허용하면 "어느 시점의 상태인가"가 모호해지고,
    속성 테스트에서 전이 전후를 비교하기 어려워집니다.
    """

    id: JobId
    kind: JobKind
    #: ⭐ 워커는 이 값으로부터 OwnerScope 를 재구성합니다 (BR-JQ-07, 경계 B).
    #: 작업 큐를 경유해 타인 데이터에 도달하는 경로를 만들지 않기 위함입니다.
    owner_id: UserId
    payload_ref: str
    state: JobState
    attempts: int
    max_attempts: int
    created_at: datetime
    updated_at: datetime
    next_attempt_at: datetime | None = None
    claimed_by: WorkerId | None = None
    heartbeat_at: datetime | None = None
    progress_percent: int = 0
    result_ref: str | None = None
    error_summary: str | None = None

    # -- 생성 ---------------------------------------------------------------
    @classmethod
    def enqueue(cls, spec: JobSpec, *, now: datetime, job_id: JobId | None = None) -> Job:
        if spec.max_attempts < 1:
            raise ValueError("max_attempts 는 1 이상이어야 합니다.")
        return cls(
            id=job_id or JobId.generate(),
            kind=spec.kind,
            owner_id=spec.owner_id,
            payload_ref=spec.payload_ref,
            state=JobState.PENDING,
            attempts=0,
            max_attempts=spec.max_attempts,
            created_at=now,
            updated_at=now,
            next_attempt_at=now,
        )

    # -- 조회 ---------------------------------------------------------------
    def is_claimable(self, now: datetime) -> bool:
        """워커가 점유할 수 있는 상태인가 (BR-JQ-02)."""
        if self.state is not JobState.PENDING:
            return False
        return self.next_attempt_at is None or self.next_attempt_at <= now

    def is_stale(self, now: datetime, timeout: timedelta) -> bool:
        """heartbeat 가 끊긴 실행 중 작업인가 (BR-JQ-04)."""
        if self.state is not JobState.RUNNING or self.heartbeat_at is None:
            return False
        return now - self.heartbeat_at > timeout

    # -- 전이 ---------------------------------------------------------------
    def claim(self, worker: WorkerId, *, now: datetime) -> Job:
        """PENDING -> RUNNING."""
        if not self.is_claimable(now):
            raise JobTransitionError(self.state, "claim")
        return replace(
            self,
            state=JobState.RUNNING,
            claimed_by=worker,
            heartbeat_at=now,
            updated_at=now,
        )

    def heartbeat(self, *, now: datetime, progress_percent: int | None = None) -> Job:
        """RUNNING -> RUNNING. 살아 있음을 알리고 진행률을 갱신한다."""
        if self.state is not JobState.RUNNING:
            raise JobTransitionError(self.state, "heartbeat")
        progress = self.progress_percent if progress_percent is None else progress_percent
        if not 0 <= progress <= 100:
            raise ValueError("progress_percent 는 0~100 이어야 합니다.")
        return replace(self, heartbeat_at=now, progress_percent=progress, updated_at=now)

    def complete(self, *, now: datetime, result_ref: str | None = None) -> Job:
        """RUNNING -> SUCCEEDED."""
        if self.state is not JobState.RUNNING:
            raise JobTransitionError(self.state, "complete")
        return replace(
            self,
            state=JobState.SUCCEEDED,
            result_ref=result_ref,
            progress_percent=100,
            claimed_by=None,
            heartbeat_at=None,
            next_attempt_at=None,
            updated_at=now,
        )

    def fail(self, *, now: datetime, reason: str, retryable: bool) -> Job:
        """RUNNING -> PENDING(재시도) 또는 FAILED.

        재시도 **불가능** 실패(형식 오류·검증 실패)는 남은 횟수와 무관하게
        즉시 종료합니다 (BR-JQ-06). 같은 입력으로 다시 시도해도 결과가
        달라지지 않기 때문입니다.
        """
        if self.state is not JobState.RUNNING:
            raise JobTransitionError(self.state, "fail")

        attempts = self.attempts + 1

        if not retryable or attempts >= self.max_attempts:
            return replace(
                self,
                state=JobState.FAILED,
                attempts=attempts,
                error_summary=reason,
                claimed_by=None,
                heartbeat_at=None,
                next_attempt_at=None,
                updated_at=now,
            )

        backoff = BACKOFF_BASE * (2 ** (attempts - 1))
        return replace(
            self,
            state=JobState.PENDING,
            attempts=attempts,
            error_summary=reason,
            claimed_by=None,
            heartbeat_at=None,
            next_attempt_at=now + backoff,
            updated_at=now,
        )

    def reap(self, *, now: datetime) -> Job:
        """RUNNING -> PENDING. 죽은 워커의 작업을 회수한다 (BR-JQ-04).

        ⭐ ``attempts`` 를 **증가시키지 않습니다.** 워커 프로세스가 죽은 것은
        작업 내용의 실패가 아닙니다. 여기서 재시도 횟수를 소모시키면
        앱 재기동이 반복될 때 정상 작업이 FAILED 로 떨어집니다.
        """
        if self.state is not JobState.RUNNING:
            raise JobTransitionError(self.state, "reap")
        return replace(
            self,
            state=JobState.PENDING,
            claimed_by=None,
            heartbeat_at=None,
            next_attempt_at=now,
            updated_at=now,
        )

    # -- 불변식 자가 검증 ----------------------------------------------------
    def check_invariants(self) -> None:
        """불변식 위반 시 ``AssertionError``.

        속성 테스트가 매 전이 후 호출합니다. 운영 경로에서는 호출하지 않습니다.
        """
        if self.state is JobState.RUNNING:
            assert self.claimed_by is not None, "INV-JB-01: RUNNING 인데 claimed_by 부재"
            assert self.heartbeat_at is not None, "INV-JB-01: RUNNING 인데 heartbeat_at 부재"
        else:
            assert self.claimed_by is None, f"INV-JB-01: {self.state} 인데 claimed_by 잔존"

        assert self.attempts <= self.max_attempts, "INV-JB-02: attempts 가 max_attempts 초과"
        assert 0 <= self.progress_percent <= 100, "progress_percent 범위 위반"
