"""헬스체크 (S13) — L-09 `HealthProbe`.

얕은 헬스체크는 **공개**, 깊은 헬스체크는 **인증 필요**입니다 (NFR-1A-31).

깊은 응답은 DB·워커·키저장소·백업 상태를 담습니다. 이것은 의존 구성 정보라
미인증 노출 시 공격 표면 파악에 쓰입니다 (SECURITY-09).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from phc.shared import ClockPort

__all__ = ["ComponentHealth", "HealthProbe", "HealthState", "HealthStatus"]

#: 개별 검사 타임아웃. 초과하면 해당 항목만 degraded 로 보고하고
#: 전체 응답은 반환합니다 — 헬스체크가 걸려서 상태를 알 수 없으면 무용합니다.
CHECK_TIMEOUT: Final = timedelta(seconds=2)


class HealthState(StrEnum):
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    name: str
    state: HealthState
    detail: str | None = None
    duration_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class HealthStatus:
    state: HealthState
    checked_at: datetime
    components: list[ComponentHealth] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return self.state is HealthState.UP


class HealthProbe:
    """얕은/깊은 헬스체크.

    깊은 검사 항목은 조립 루트에서 등록합니다. ``operations`` 가 다른 도메인을
    직접 참조하지 않기 위함입니다 (계약 C1).
    """

    def __init__(self, *, clock: ClockPort) -> None:
        self._clock = clock
        self._deep_checks: dict[str, Callable[[], ComponentHealth]] = {}

    def register_deep_check(self, name: str, check: Callable[[], ComponentHealth]) -> None:
        self._deep_checks[name] = check

    def shallow(self) -> HealthStatus:
        """프로세스 생존만 확인한다. 공개 엔드포인트."""
        return HealthStatus(state=HealthState.UP, checked_at=self._clock.now())

    def deep(self) -> HealthStatus:
        """DB · 워커 · 키저장소 · 백업 상태를 확인한다. 인증 필요."""
        components: list[ComponentHealth] = []

        for name, check in self._deep_checks.items():
            started = time.perf_counter()
            try:
                result = check()
            except Exception as exc:  # 광범위 포착 사유: 한 항목 실패가 전체를 막지 않게
                result = ComponentHealth(
                    name=name,
                    state=HealthState.DOWN,
                    detail=type(exc).__name__,
                )
            elapsed_ms = (time.perf_counter() - started) * 1000

            if elapsed_ms > CHECK_TIMEOUT.total_seconds() * 1000 and result.state is HealthState.UP:
                result = ComponentHealth(
                    name=name,
                    state=HealthState.DEGRADED,
                    detail="검사 시간 초과",
                    duration_ms=elapsed_ms,
                )
            else:
                result = ComponentHealth(
                    name=result.name,
                    state=result.state,
                    detail=result.detail,
                    duration_ms=elapsed_ms,
                )
            components.append(result)

        return HealthStatus(
            state=self._aggregate(components),
            checked_at=self._clock.now(),
            components=components,
        )

    @staticmethod
    def _aggregate(components: list[ComponentHealth]) -> HealthState:
        if any(c.state is HealthState.DOWN for c in components):
            return HealthState.DOWN
        if any(c.state is HealthState.DEGRADED for c in components):
            return HealthState.DEGRADED
        return HealthState.UP
