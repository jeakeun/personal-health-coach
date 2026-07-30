"""시각 포트.

시각을 주입 가능하게 두는 이유는 편의가 아니라 **재현성**입니다 (NFR-27).

세션 만료 · 스로틀 잠금 · 작업 heartbeat 만료는 전부 시각 비교입니다.
``datetime.now()`` 를 직접 부르면 속성 테스트에서 경계 조건을 만들 수 없고,
실패한 반례를 재현할 수도 없습니다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

__all__ = ["ClockPort", "FixedClock", "SystemClock"]


class ClockPort(Protocol):
    """현재 시각 제공자."""

    def now(self) -> datetime:
        """timezone-aware UTC 시각을 반환한다."""
        ...


class SystemClock:
    """실제 시스템 시각. 운영 구현."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """테스트용 고정 시각.

    ``advance()`` 로 시간을 앞으로 밀 수 있습니다. 세션 만료 경계
    (유휴 59분59초 / 60분01초) 같은 검증이 실시간 대기 없이 가능해집니다.
    """

    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None:
            raise ValueError("FixedClock 은 timezone-aware datetime 을 요구합니다.")
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta

    def set(self, moment: datetime) -> None:
        if moment.tzinfo is None:
            raise ValueError("timezone-aware datetime 이 필요합니다.")
        self._now = moment
