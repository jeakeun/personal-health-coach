"""🔬 PBT 속성 4 — 작업 큐 상태 전이 (PBT-06 상태 기반).

**진술**: 임의의 연산 시퀀스(enqueue · claim · heartbeat · complete · fail ·
reap)에 대해

    (a) 종료 상태에서 나가는 전이가 발생하지 않고
    (b) attempts <= max_attempts 가 항상 참이며
    (c) RUNNING 인 작업은 항상 claimed_by 와 heartbeat_at 을 가진다.

반례가 잡는 것:
    완료된 작업의 재실행 · 무한 재시도 · 회수 로직이 종료 작업을 되살리는 버그

재현성 (NFR-27):
    시각은 ``FixedClock`` 으로 주입합니다. 실시간에 의존하면 실패한 반례를
    재현할 수 없습니다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import HealthCheck, settings
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule
from hypothesis.strategies import booleans, integers, sampled_from

from phc.operations.domain.job import (
    Job,
    JobKind,
    JobSpec,
    JobState,
    JobTransitionError,
    WorkerId,
)
from phc.shared import AuthContext, OwnerScope, Role, UserId

pytestmark = pytest.mark.property

_START = datetime(2026, 1, 1, tzinfo=UTC)
_HEARTBEAT_TIMEOUT = timedelta(minutes=5)


def _scope(owner: str) -> OwnerScope:
    return OwnerScope.for_subject(AuthContext(UserId(owner), Role.USER))


class JobStateMachine(RuleBasedStateMachine):
    """단일 작업에 임의의 연산 시퀀스를 가한다.

    허용되지 않은 전이는 ``JobTransitionError`` 를 던지는 것이 **정상 동작**
    입니다. 그것까지 확인하기 위해 예외를 삼키지 않고 상태 변화가 없었음을
    검증합니다.
    """

    def __init__(self) -> None:
        super().__init__()
        self.now = _START
        self.job: Job | None = None
        self.max_attempts = 3
        self.terminal_seen_at: JobState | None = None

    @initialize(max_attempts=integers(min_value=1, max_value=5))
    def create(self, max_attempts: int) -> None:
        self.max_attempts = max_attempts
        spec = JobSpec.for_scope(JobKind.BACKUP, _scope("owner-1"), max_attempts=max_attempts)
        self.job = Job.enqueue(spec, now=self.now)

    # -- 시간 진행 -----------------------------------------------------------
    @rule(minutes=integers(min_value=0, max_value=30))
    def advance_time(self, minutes: int) -> None:
        self.now += timedelta(minutes=minutes)

    # -- 전이 ---------------------------------------------------------------
    @rule(worker=sampled_from(["w1", "w2"]))
    def claim(self, worker: str) -> None:
        assert self.job is not None
        before = self.job
        try:
            self.job = self.job.claim(WorkerId(worker), now=self.now)
        except JobTransitionError:
            # 점유 불가 상태였다면 아무것도 바뀌지 않아야 한다
            assert self.job is before

    @rule(progress=integers(min_value=0, max_value=100))
    def heartbeat(self, progress: int) -> None:
        assert self.job is not None
        before = self.job
        try:
            self.job = self.job.heartbeat(now=self.now, progress_percent=progress)
        except JobTransitionError:
            assert self.job is before

    @rule()
    def complete(self) -> None:
        assert self.job is not None
        before = self.job
        try:
            self.job = self.job.complete(now=self.now)
        except JobTransitionError:
            assert self.job is before

    @rule(retryable=booleans())
    def fail(self, retryable: bool) -> None:
        assert self.job is not None
        before = self.job
        try:
            self.job = self.job.fail(now=self.now, reason="test", retryable=retryable)
        except JobTransitionError:
            assert self.job is before

    @rule()
    def reap(self) -> None:
        assert self.job is not None
        before = self.job
        if not before.is_stale(self.now, _HEARTBEAT_TIMEOUT):
            return
        attempts_before = before.attempts
        self.job = before.reap(now=self.now)
        # ⭐ 회수는 재시도 횟수를 소모하지 않는다 (BR-JQ-04)
        assert self.job.attempts == attempts_before

    # -- 불변식 --------------------------------------------------------------
    @invariant()
    def domain_invariants_hold(self) -> None:
        if self.job is None:
            return
        self.job.check_invariants()

    @invariant()
    def terminal_states_are_absorbing(self) -> None:
        """(a) 종료 상태에서 나가는 전이가 없다 (INV-JB-03)."""
        if self.job is None:
            return
        if self.terminal_seen_at is not None:
            assert self.job.state is self.terminal_seen_at, (
                f"종료 상태 {self.terminal_seen_at} 에서 {self.job.state} 로 전이됨"
            )
        elif self.job.state.is_terminal:
            self.terminal_seen_at = self.job.state

    @invariant()
    def attempts_never_exceed_max(self) -> None:
        """(b) attempts <= max_attempts (INV-JB-02)."""
        if self.job is None:
            return
        assert self.job.attempts <= self.max_attempts

    @invariant()
    def running_jobs_are_owned(self) -> None:
        """(c) RUNNING 이면 claimed_by 와 heartbeat_at 이 있다 (INV-JB-01)."""
        if self.job is None:
            return
        if self.job.state is JobState.RUNNING:
            assert self.job.claimed_by is not None
            assert self.job.heartbeat_at is not None


TestJobStateMachine = JobStateMachine.TestCase
TestJobStateMachine.settings = settings(
    max_examples=200,
    stateful_step_count=40,
    suppress_health_check=[HealthCheck.too_slow],
)
