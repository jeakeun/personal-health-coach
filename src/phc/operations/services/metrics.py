"""메트릭 수집 (S13) — L-08 `MetricsRegistry`.

인메모리 수집입니다. 재기동 시 초기화되며, 장기 추이는 감사 로그가 담당합니다
(NFR-1A-30).

⭐ ``password.hash.duration`` 히스토그램은 단순한 관측 지표가 아니라
   **Argon2id 파라미터 조정의 근거 데이터**입니다.
   성능 예산(<=500ms)이 보안 강도의 상한 역할을 하므로, 실측이 150ms 를
   밑돌면 강도를 올립니다 (nfr-requirements.md §2.1).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Final

__all__ = ["MetricName", "MetricsRegistry", "MetricsSnapshot"]


class MetricName:
    """지표 이름 상수 (nfr-design-patterns.md §5.2)."""

    LOGIN_SUCCESS: Final = "login.success"
    LOGIN_FAILURE: Final = "login.failure"
    LOGIN_BLOCKED: Final = "login.blocked"
    #: ⭐ 경계 B 위반 시도 탐지
    AUTHZ_DENIED: Final = "authz.denied"
    SESSION_ACTIVE: Final = "session.active"
    JOB_PENDING: Final = "job.pending"
    JOB_RUNNING: Final = "job.running"
    JOB_FAILED: Final = "job.failed"
    BACKUP_SUCCESS: Final = "backup.success"
    BACKUP_FAILURE: Final = "backup.failure"
    HTTP_REQUEST_DURATION: Final = "http.request.duration"
    #: ⭐ Argon2id 파라미터 조정 근거 (린트 예외: 지표 이름이며 비밀번호가 아님)
    PASSWORD_HASH_DURATION: Final = "password.hash.duration"  # noqa: S105
    ERROR_UNHANDLED: Final = "error.unhandled"


@dataclass(frozen=True, slots=True)
class Histogram:
    count: int
    total: float
    min_value: float
    max_value: float
    p95: float

    @property
    def mean(self) -> float:
        return self.total / self.count if self.count else 0.0


@dataclass(frozen=True, slots=True)
class MetricsSnapshot:
    counters: dict[str, int] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    histograms: dict[str, Histogram] = field(default_factory=dict)


class MetricsRegistry:
    """스레드 안전 인메모리 메트릭 수집기.

    워커 스레드와 웹 요청이 동시에 기록하므로 잠금이 필요합니다.
    """

    #: 히스토그램은 최근 N 개 관측만 보관합니다. 무한히 쌓이면 메모리가 샙니다.
    MAX_OBSERVATIONS: Final = 1000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._observations: dict[str, list[float]] = {}

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            series = self._observations.setdefault(name, [])
            series.append(value)
            if len(series) > self.MAX_OBSERVATIONS:
                del series[: len(series) - self.MAX_OBSERVATIONS]

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            histograms = {
                name: self._summarize(values)
                for name, values in self._observations.items()
                if values
            }
            return MetricsSnapshot(
                counters=dict(self._counters),
                gauges=dict(self._gauges),
                histograms=histograms,
            )

    @staticmethod
    def _summarize(values: list[float]) -> Histogram:
        ordered = sorted(values)
        # 최근접 순위법. 관측 수가 적을 때 보간하면 없는 값을 만들어 냅니다.
        index = max(0, min(len(ordered) - 1, round(0.95 * len(ordered)) - 1))
        return Histogram(
            count=len(ordered),
            total=sum(ordered),
            min_value=ordered[0],
            max_value=ordered[-1],
            p95=ordered[index],
        )

    def reset(self) -> None:
        """테스트 전용."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._observations.clear()
