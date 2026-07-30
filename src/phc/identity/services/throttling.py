"""무차별 대입 방어 (S20, F2=A).

⭐ 이 모듈의 핵심은 **응답 동일성**입니다.

   지연과 잠금을 아무리 정교하게 만들어도, 존재하지 않는 사용자명일 때만
   빠르게 응답하면 **응답 시간만으로 유효한 사용자명 목록을 만들 수 있습니다**.
   그것이 US-45 의 실질적 인수 조건입니다 (BR-TH-10~13).
"""

from __future__ import annotations

import time
from datetime import timedelta

from phc.identity.domain.throttle import (
    DEFAULT_LOCKOUT_DURATION,
    DEFAULT_LOCKOUT_THRESHOLD,
    AttemptOutcome,
    LoginAttempt,
    ThrottleDecision,
    ThrottleKey,
    ThrottleState,
)
from phc.identity.ports.repositories import ThrottleRepositoryPort
from phc.shared import ClockPort, DomainError, UndeterminedError

__all__ = ["LoginThrottle"]


class LoginThrottle:
    def __init__(
        self,
        *,
        repository: ThrottleRepositoryPort,
        clock: ClockPort,
        threshold: int = DEFAULT_LOCKOUT_THRESHOLD,
        lockout_duration: timedelta = DEFAULT_LOCKOUT_DURATION,
        sleep: object = None,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._threshold = threshold
        self._lockout_duration = lockout_duration
        # 테스트에서 실제로 잠들지 않도록 주입 가능하게 둡니다.
        self._sleep = sleep if callable(sleep) else time.sleep

    # -- 판정 ---------------------------------------------------------------
    def check(self, key: ThrottleKey) -> ThrottleDecision:
        """스로틀 판정.

        ⛔ 상태를 조회할 수 없으면 ``UndeterminedError`` — 로그인을
        **거부**해야 합니다 (BR-TH-06). 스로틀 상태를 모르는 채 통과시키면
        방어가 없는 것과 같습니다.
        """
        try:
            state = self._repository.get_state(key)
        except DomainError:
            raise
        except Exception as exc:
            raise UndeterminedError(
                "throttle_state", detail=f"스로틀 조회 실패: {type(exc).__name__}"
            ) from exc

        if state is None:
            return ThrottleDecision(allowed=True, delay_seconds=0)
        return state.decide(self._clock.now())

    def apply_delay(self, decision: ThrottleDecision) -> None:
        """응답 전 지연을 적용한다 (BR-TH-02).

        ⭐ 계정 존재 여부와 무관하게 적용됩니다. 지연이 한쪽 경로에만
        걸리면 그 차이가 곧 정보입니다.
        """
        if decision.delay_seconds > 0:
            self._sleep(decision.delay_seconds)

    # -- 기록 ---------------------------------------------------------------
    def record_failure(self, key: ThrottleKey, outcome: AttemptOutcome) -> ThrottleState:
        """실패를 기록한다.

        ⚠ 저장은 **인증 트랜잭션과 별도로 커밋**되어야 합니다 (BR-TX-02).
        인증 실패로 롤백되면 카운터도 되돌아가 방어가 무력화됩니다.
        """
        now = self._clock.now()
        state = self._repository.get_state(key) or ThrottleState(key=key)
        updated = state.record_failure(
            now=now, threshold=self._threshold, duration=self._lockout_duration
        )
        self._repository.save_state(updated)
        self._repository.record_attempt(
            LoginAttempt(
                username_normalized=key.username_normalized,
                client_key=key.client_key,
                occurred_at=now,
                outcome=outcome,
            )
        )
        return updated

    def record_success(self, key: ThrottleKey) -> None:
        """INV-TH-02 — 카운터를 초기화한다."""
        now = self._clock.now()
        state = self._repository.get_state(key) or ThrottleState(key=key)
        self._repository.save_state(state.record_success())
        self._repository.record_attempt(
            LoginAttempt(
                username_normalized=key.username_normalized,
                client_key=key.client_key,
                occurred_at=now,
                outcome=AttemptOutcome.SUCCESS,
            )
        )

    # -- 알림 판정 -----------------------------------------------------------
    def failures_in_window(self, username_normalized: str, window: timedelta) -> int:
        since = self._clock.now() - window
        return self._repository.count_failures_since(username_normalized, since)

    def all_failures_in_window(self, window: timedelta) -> int:
        since = self._clock.now() - window
        return self._repository.count_all_failures_since(since)
