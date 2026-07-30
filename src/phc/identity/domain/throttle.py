"""무차별 대입 방어 도메인 (S17, F2=A).

정책:
    지연  실패 0/1/2/4/8초 (상한 8초)
    잠금  연속 실패 10회 초과 시 15분, **시간 경과로 자동 해제**

⭐ ``ThrottleState`` 는 ``Account`` 를 참조하지 않습니다.
   존재하지 않는 사용자명에 대해서도 상태를 유지해야 계정 열거를 막을 수
   있기 때문입니다 (BR-TH-11).

불변식:
    INV-TH-01  locked_until 이 과거이면 잠금은 해제된 것으로 판정한다
    INV-TH-02  인증 성공 시 카운터가 0 으로 초기화된다
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

__all__ = [
    "DEFAULT_LOCKOUT_DURATION",
    "DEFAULT_LOCKOUT_THRESHOLD",
    "MAX_DELAY_SECONDS",
    "AttemptOutcome",
    "LoginAttempt",
    "ThrottleDecision",
    "ThrottleKey",
    "ThrottleState",
]

DEFAULT_LOCKOUT_THRESHOLD: Final = 10
DEFAULT_LOCKOUT_DURATION: Final = timedelta(minutes=15)
MAX_DELAY_SECONDS: Final = 8


class AttemptOutcome(StrEnum):
    SUCCESS = "success"
    BAD_CREDENTIALS = "bad_credentials"
    INACTIVE = "inactive"
    MFA_FAILED = "mfa_failed"
    THROTTLED = "throttled"

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ThrottleKey:
    """``(정규화된 사용자명, 클라이언트 식별자)`` 조합.

    ⚠ 로컬 루프백 실행에서는 ``client_key`` 의 변별력이 사실상 없습니다
    (원격 IP 가 항상 127.0.0.1). **실질적 주 방어는 사용자명 성분**이며,
    ``client_key`` 는 클라우드 이전 시를 위한 구조입니다 (ND9=A).
    """

    username_normalized: str
    client_key: str

    def __redacted_repr__(self) -> str:
        return f"ThrottleKey({self.username_normalized})"


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    """로그인 시도 기록.

    ⭐ 계정이 존재하지 않아도 기록합니다. 존재 여부에 따라 기록이 갈리면
    **응답 시간 차이로 계정 존재가 드러납니다** (BR-TH-11).
    """

    username_normalized: str
    client_key: str
    occurred_at: datetime
    outcome: AttemptOutcome


@dataclass(frozen=True, slots=True)
class ThrottleDecision:
    """스로틀 판정 결과."""

    allowed: bool
    delay_seconds: int
    locked_until: datetime | None = None

    def __redacted_repr__(self) -> str:
        return f"ThrottleDecision(allowed={self.allowed}, delay={self.delay_seconds})"


@dataclass(frozen=True, slots=True)
class ThrottleState:
    """키별 실패 누적 상태."""

    key: ThrottleKey
    consecutive_failures: int = 0
    first_failure_at: datetime | None = None
    last_failure_at: datetime | None = None
    locked_until: datetime | None = None

    # -- 판정 ---------------------------------------------------------------
    def is_locked(self, now: datetime) -> bool:
        """INV-TH-01 — 시간 경과로 자동 해제. 별도 해제 작업이 없습니다."""
        return self.locked_until is not None and now < self.locked_until

    def delay_seconds(self) -> int:
        """실패 누적에 따른 지연: 0 / 1 / 2 / 4 / 8 (상한 8초)."""
        if self.consecutive_failures <= 0:
            return 0
        return min(int(2 ** (self.consecutive_failures - 1)), MAX_DELAY_SECONDS)

    def decide(self, now: datetime) -> ThrottleDecision:
        if self.is_locked(now):
            return ThrottleDecision(
                allowed=False,
                delay_seconds=self.delay_seconds(),
                locked_until=self.locked_until,
            )
        return ThrottleDecision(allowed=True, delay_seconds=self.delay_seconds())

    # -- 전이 ---------------------------------------------------------------
    def record_failure(
        self,
        *,
        now: datetime,
        threshold: int = DEFAULT_LOCKOUT_THRESHOLD,
        duration: timedelta = DEFAULT_LOCKOUT_DURATION,
    ) -> ThrottleState:
        failures = self.consecutive_failures + 1
        locked_until = now + duration if failures > threshold else self.locked_until
        return replace(
            self,
            consecutive_failures=failures,
            first_failure_at=self.first_failure_at or now,
            last_failure_at=now,
            locked_until=locked_until,
        )

    def record_success(self) -> ThrottleState:
        """INV-TH-02 — 성공하면 초기화."""
        return ThrottleState(key=self.key)

    def __redacted_repr__(self) -> str:
        return f"ThrottleState({self.key.username_normalized}, fails={self.consecutive_failures})"
