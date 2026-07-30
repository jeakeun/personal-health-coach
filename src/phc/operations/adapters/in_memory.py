"""인메모리 어댑터 (S16).

⭐ 이 어댑터들은 편의 도구가 아니라 **요구사항의 검증 수단**입니다.

    NFR-1A-38 의 판정 기준이 "인메모리 리포지토리 구현으로 도메인 테스트가
    통과하는가" 입니다. 도메인 모델이 SQLAlchemy 에 종속되면 이 구현을
    만들 수 없고, 그 사실이 곧 판정 실패입니다.

    Phase 4 에서 SQL 어댑터를 만든 뒤 **같은 계약 테스트를 두 구현에 모두**
    적용합니다 (S29).
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

from phc.operations.domain.alert import Alert, AlertId, AlertKind
from phc.operations.domain.audit import AuditEntry, AuditEventType
from phc.operations.domain.backup import BackupArtifact, BackupId
from phc.operations.domain.job import Job, JobId, JobSpec, WorkerId
from phc.operations.ports.audit import AuditFilter

__all__ = [
    "InMemoryAlertStore",
    "InMemoryAuditTrail",
    "InMemoryBackupStore",
    "InMemoryJobQueue",
]


class InMemoryAuditTrail:
    """append-only 감사 기록.

    ⭐ ``update`` · ``delete`` 메서드가 **없습니다.** 포트에 없으므로
    구현에도 없습니다 (NFR-10).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[AuditEntry] = []

    def append(self, entry: AuditEntry) -> AuditEntry:
        from dataclasses import replace

        with self._lock:
            stored = replace(entry, seq=len(self._entries) + 1)
            self._entries.append(stored)
            return stored

    def query(self, criteria: AuditFilter) -> list[AuditEntry]:
        with self._lock:
            result = list(reversed(self._entries))

        if criteria.event_types is not None:
            result = [e for e in result if e.event_type in criteria.event_types]
        if criteria.actor_user_id is not None:
            result = [e for e in result if e.actor_user_id == criteria.actor_user_id]
        if criteria.since is not None:
            result = [e for e in result if e.occurred_at >= criteria.since]
        if criteria.until is not None:
            result = [e for e in result if e.occurred_at <= criteria.until]

        return result[: criteria.limit]

    def count_since(self, event_type: AuditEventType, since: datetime) -> int:
        with self._lock:
            return sum(
                1 for e in self._entries if e.event_type is event_type and e.occurred_at >= since
            )

    def max_seq(self) -> int:
        with self._lock:
            return len(self._entries)


class InMemoryJobQueue:
    """DB 작업 테이블의 인메모리 대응물.

    ``claim`` 은 잠금 안에서 상태를 바꿔, 두 워커가 같은 작업을 점유하지
    않게 합니다. SQL 구현에서는 조건부 UPDATE 가 같은 역할을 합니다.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[JobId, Job] = {}

    def enqueue(self, spec: JobSpec, *, now: datetime) -> Job:
        job = Job.enqueue(spec, now=now)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def claim(self, worker: WorkerId, *, now: datetime) -> Job | None:
        with self._lock:
            for job in sorted(self._jobs.values(), key=lambda j: j.created_at):
                if job.is_claimable(now):
                    claimed = job.claim(worker, now=now)
                    self._jobs[claimed.id] = claimed
                    return claimed
            return None

    def save(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def get(self, job_id: JobId) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def find_stale(self, *, now: datetime, timeout: timedelta) -> list[Job]:
        with self._lock:
            return [j for j in self._jobs.values() if j.is_stale(now, timeout)]

    def count_by_state(self) -> dict[str, int]:
        with self._lock:
            counts: dict[str, int] = {}
            for job in self._jobs.values():
                counts[job.state.value] = counts.get(job.state.value, 0) + 1
            return counts

    def all_jobs(self) -> list[Job]:
        """테스트 전용 — 불변식 전수 검사에 사용."""
        with self._lock:
            return list(self._jobs.values())


class InMemoryAlertStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alerts: dict[AlertId, Alert] = {}

    def save(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.id] = alert

    def get(self, alert_id: AlertId) -> Alert | None:
        with self._lock:
            return self._alerts.get(alert_id)

    def list_open(self, *, limit: int = 100) -> list[Alert]:
        with self._lock:
            openish = [a for a in self._alerts.values() if a.is_open]
        return sorted(openish, key=lambda a: a.raised_at, reverse=True)[:limit]

    def last_raised_at(self, kind: AlertKind) -> datetime | None:
        with self._lock:
            times = [a.raised_at for a in self._alerts.values() if a.kind is kind]
        return max(times) if times else None


class InMemoryBackupStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._artifacts: dict[BackupId, BackupArtifact] = {}

    def save(self, artifact: BackupArtifact) -> None:
        with self._lock:
            self._artifacts[artifact.id] = artifact

    def get(self, backup_id: BackupId) -> BackupArtifact | None:
        with self._lock:
            return self._artifacts.get(backup_id)

    def list_all(self) -> list[BackupArtifact]:
        with self._lock:
            return sorted(self._artifacts.values(), key=lambda a: a.created_at, reverse=True)

    def delete(self, backup_id: BackupId) -> None:
        with self._lock:
            self._artifacts.pop(backup_id, None)

    def last_successful_at(self) -> datetime | None:
        with self._lock:
            times = [a.created_at for a in self._artifacts.values()]
        return max(times) if times else None
