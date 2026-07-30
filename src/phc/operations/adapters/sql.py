"""operations SQL 어댑터 (S28, D-04 SQLAlchemy Core).

⭐ ``SqlAuditTrail`` 에 **갱신·삭제 메서드가 없습니다.** 포트에 없으므로
   구현에도 없습니다 (NFR-10, BR-AU-01). 감사 정리는 애플리케이션이 아니라
   운영 스크립트가 수행합니다 (F9=A).

⭐ ``SqlJobQueue.claim`` 은 **조건부 UPDATE** 로 점유합니다. SELECT 후 UPDATE
   하면 두 워커가 같은 행을 읽어 둘 다 점유할 수 있습니다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Row, delete, func, insert, select, update

from phc.infrastructure.db.engine import Database
from phc.infrastructure.db.schema import (
    alerts,
    audit_entries,
    backup_artifacts,
    jobs,
)
from phc.operations.domain.alert import Alert, AlertId, AlertKind, AlertSeverity
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.domain.backup import BackupArtifact, BackupId
from phc.operations.domain.job import Job, JobId, JobKind, JobSpec, JobState, WorkerId
from phc.operations.ports.audit import AuditFilter
from phc.shared import Role, UserId

__all__ = ["SqlAlertStore", "SqlAuditTrail", "SqlBackupStore", "SqlJobQueue"]


def _aware(value: datetime | None) -> datetime | None:
    """SQLite 가 잃어버린 timezone 을 UTC 로 되살립니다 (identity/adapters/sql.py 와 동일)."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _required(value: datetime | None) -> datetime:
    aware = _aware(value)
    if aware is None:
        raise ValueError("필수 시각 컬럼이 비어 있습니다.")
    return aware


# ---------------------------------------------------------------------------
# 감사 — append-only
# ---------------------------------------------------------------------------
class SqlAuditTrail:
    """⭐ ``update`` · ``delete`` 가 없습니다 (NFR-10)."""

    def __init__(self, database: Database) -> None:
        self._db = database

    @staticmethod
    def _to_domain(row: Row[Any]) -> AuditEntry:
        return AuditEntry(
            event_type=AuditEventType(row.event_type),
            outcome=AuditOutcome(row.outcome),
            occurred_at=_required(row.occurred_at),
            actor_user_id=UserId(row.actor_user_id) if row.actor_user_id else None,
            actor_role=Role(row.actor_role) if row.actor_role else None,
            target_ref=row.target_ref,
            correlation_id=row.correlation_id,
            detail=dict(row.detail or {}),
            seq=row.seq,
        )

    def append(self, entry: AuditEntry) -> AuditEntry:
        from dataclasses import replace

        with self._db.transaction() as conn:
            result = conn.execute(
                insert(audit_entries).values(
                    occurred_at=entry.occurred_at,
                    event_type=entry.event_type.value,
                    outcome=entry.outcome.value,
                    actor_user_id=entry.actor_user_id.value if entry.actor_user_id else None,
                    actor_role=entry.actor_role.value if entry.actor_role else None,
                    target_ref=entry.target_ref,
                    correlation_id=entry.correlation_id,
                    # ⚠ Redactable 만 담깁니다. 민감 타입은 애플리케이션 계층
                    #    타입 검사에서 이미 막혀 여기 도달하지 않습니다.
                    detail={k: str(v) for k, v in entry.detail.items()},
                )
            )
            seq = result.inserted_primary_key[0] if result.inserted_primary_key else None

        return replace(entry, seq=seq)

    def query(self, criteria: AuditFilter) -> list[AuditEntry]:
        statement = select(audit_entries).order_by(audit_entries.c.seq.desc())

        if criteria.event_types is not None:
            statement = statement.where(
                audit_entries.c.event_type.in_([e.value for e in criteria.event_types])
            )
        if criteria.actor_user_id is not None:
            statement = statement.where(
                audit_entries.c.actor_user_id == criteria.actor_user_id.value
            )
        if criteria.since is not None:
            statement = statement.where(audit_entries.c.occurred_at >= criteria.since)
        if criteria.until is not None:
            statement = statement.where(audit_entries.c.occurred_at <= criteria.until)

        with self._db.connect() as conn:
            rows = conn.execute(statement.limit(criteria.limit)).all()
        return [self._to_domain(row) for row in rows]

    def count_since(self, event_type: AuditEventType, since: datetime) -> int:
        with self._db.connect() as conn:
            result = conn.execute(
                select(func.count())
                .select_from(audit_entries)
                .where(
                    audit_entries.c.event_type == event_type.value,
                    audit_entries.c.occurred_at >= since,
                )
            ).scalar_one()
        return int(result)

    def max_seq(self) -> int:
        with self._db.connect() as conn:
            result = conn.execute(select(func.max(audit_entries.c.seq))).scalar()
        return int(result or 0)


# ---------------------------------------------------------------------------
# 작업 큐
# ---------------------------------------------------------------------------
class SqlJobQueue:
    def __init__(self, database: Database) -> None:
        self._db = database

    @staticmethod
    def _to_domain(row: Row[Any]) -> Job:
        return Job(
            id=JobId(row.id),
            kind=JobKind(row.kind),
            owner_id=UserId(row.owner_id),
            payload_ref=row.payload_ref,
            state=JobState(row.state),
            attempts=row.attempts,
            max_attempts=row.max_attempts,
            created_at=_required(row.created_at),
            updated_at=_required(row.updated_at),
            next_attempt_at=_aware(row.next_attempt_at),
            claimed_by=WorkerId(row.claimed_by) if row.claimed_by else None,
            heartbeat_at=_aware(row.heartbeat_at),
            progress_percent=row.progress_percent,
            result_ref=row.result_ref,
            error_summary=row.error_summary,
        )

    @staticmethod
    def _to_values(job: Job) -> dict[str, Any]:
        return {
            "id": job.id.value,
            "kind": job.kind.value,
            "owner_id": job.owner_id.value,
            "payload_ref": job.payload_ref,
            "state": job.state.value,
            "attempts": job.attempts,
            "max_attempts": job.max_attempts,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
            "next_attempt_at": job.next_attempt_at,
            "claimed_by": job.claimed_by.value if job.claimed_by else None,
            "heartbeat_at": job.heartbeat_at,
            "progress_percent": job.progress_percent,
            "result_ref": job.result_ref,
            "error_summary": job.error_summary,
        }

    def enqueue(self, spec: JobSpec, *, now: datetime) -> Job:
        job = Job.enqueue(spec, now=now)
        with self._db.transaction() as conn:
            conn.execute(insert(jobs).values(**self._to_values(job)))
        return job

    def claim(self, worker: WorkerId, *, now: datetime) -> Job | None:
        """⭐ 조건부 UPDATE 로 점유한다.

        SELECT 후 UPDATE 하면 두 워커가 같은 행을 읽어 둘 다 점유할 수
        있습니다. ``state == PENDING`` 조건을 UPDATE 의 WHERE 에 넣어,
        먼저 커밋한 쪽만 성공하게 합니다.
        """
        with self._db.transaction() as conn:
            candidate = conn.execute(
                select(jobs.c.id)
                .where(
                    jobs.c.state == JobState.PENDING.value,
                    (jobs.c.next_attempt_at.is_(None)) | (jobs.c.next_attempt_at <= now),
                )
                .order_by(jobs.c.created_at)
                .limit(1)
            ).one_or_none()

            if candidate is None:
                return None

            result = conn.execute(
                update(jobs)
                .where(
                    jobs.c.id == candidate.id,
                    jobs.c.state == JobState.PENDING.value,  # ← 경쟁 방어
                )
                .values(
                    state=JobState.RUNNING.value,
                    claimed_by=worker.value,
                    heartbeat_at=now,
                    updated_at=now,
                )
            )
            if not result.rowcount:
                return None  # 다른 워커가 먼저 가져갔습니다

            row = conn.execute(select(jobs).where(jobs.c.id == candidate.id)).one()
            return self._to_domain(row)

    def save(self, job: Job) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                update(jobs).where(jobs.c.id == job.id.value).values(**self._to_values(job))
            )

    def get(self, job_id: JobId) -> Job | None:
        with self._db.connect() as conn:
            row = conn.execute(select(jobs).where(jobs.c.id == job_id.value)).one_or_none()
        return self._to_domain(row) if row is not None else None

    def find_stale(self, *, now: datetime, timeout: timedelta) -> list[Job]:
        with self._db.connect() as conn:
            rows = conn.execute(
                select(jobs).where(
                    jobs.c.state == JobState.RUNNING.value,
                    jobs.c.heartbeat_at.is_not(None),
                    jobs.c.heartbeat_at < now - timeout,
                )
            ).all()
        return [self._to_domain(row) for row in rows]

    def count_by_state(self) -> dict[str, int]:
        with self._db.connect() as conn:
            rows = conn.execute(select(jobs.c.state, func.count()).group_by(jobs.c.state)).all()
        return {row[0]: int(row[1]) for row in rows}


# ---------------------------------------------------------------------------
# 알림
# ---------------------------------------------------------------------------
class SqlAlertStore:
    def __init__(self, database: Database) -> None:
        self._db = database

    @staticmethod
    def _to_domain(row: Row[Any]) -> Alert:
        return Alert(
            id=AlertId(row.id),
            kind=AlertKind(row.kind),
            severity=AlertSeverity(row.severity),
            raised_at=_required(row.raised_at),
            summary=row.summary,
            context=dict(row.context or {}),
            acknowledged_at=_aware(row.acknowledged_at),
        )

    def save(self, alert: Alert) -> None:
        values = {
            "id": alert.id.value,
            "kind": alert.kind.value,
            "severity": alert.severity.value,
            "raised_at": alert.raised_at,
            "summary": alert.summary,
            "context": {k: str(v) for k, v in alert.context.items()},
            "acknowledged_at": alert.acknowledged_at,
        }
        with self._db.transaction() as conn:
            existing = conn.execute(
                select(alerts.c.id).where(alerts.c.id == alert.id.value)
            ).one_or_none()
            if existing is None:
                conn.execute(insert(alerts).values(**values))
            else:
                conn.execute(update(alerts).where(alerts.c.id == alert.id.value).values(**values))

    def get(self, alert_id: AlertId) -> Alert | None:
        with self._db.connect() as conn:
            row = conn.execute(select(alerts).where(alerts.c.id == alert_id.value)).one_or_none()
        return self._to_domain(row) if row is not None else None

    def list_open(self, *, limit: int = 100) -> list[Alert]:
        with self._db.connect() as conn:
            rows = conn.execute(
                select(alerts)
                .where(alerts.c.acknowledged_at.is_(None))
                .order_by(alerts.c.raised_at.desc())
                .limit(limit)
            ).all()
        return [self._to_domain(row) for row in rows]

    def last_raised_at(self, kind: AlertKind) -> datetime | None:
        with self._db.connect() as conn:
            result = conn.execute(
                select(func.max(alerts.c.raised_at)).where(alerts.c.kind == kind.value)
            ).scalar()
        return _aware(result)


# ---------------------------------------------------------------------------
# 백업 메타데이터
# ---------------------------------------------------------------------------
class SqlBackupStore:
    def __init__(self, database: Database) -> None:
        self._db = database

    @staticmethod
    def _to_domain(row: Row[Any]) -> BackupArtifact:
        return BackupArtifact(
            id=BackupId(row.id),
            created_at=_required(row.created_at),
            artifact_ref=row.artifact_ref,
            size_bytes=row.size_bytes,
            checksum=row.checksum,
            cipher_key_ref=row.cipher_key_ref,
            schema_version=row.schema_version,
            verified_at=_aware(row.verified_at),
        )

    def save(self, artifact: BackupArtifact) -> None:
        values = {
            "id": artifact.id.value,
            "created_at": artifact.created_at,
            "artifact_ref": artifact.artifact_ref,
            "size_bytes": artifact.size_bytes,
            "checksum": artifact.checksum,
            "cipher_key_ref": artifact.cipher_key_ref,
            "schema_version": artifact.schema_version,
            "verified_at": artifact.verified_at,
        }
        with self._db.transaction() as conn:
            existing = conn.execute(
                select(backup_artifacts.c.id).where(backup_artifacts.c.id == artifact.id.value)
            ).one_or_none()
            if existing is None:
                conn.execute(insert(backup_artifacts).values(**values))
            else:
                conn.execute(
                    update(backup_artifacts)
                    .where(backup_artifacts.c.id == artifact.id.value)
                    .values(**values)
                )

    def get(self, backup_id: BackupId) -> BackupArtifact | None:
        with self._db.connect() as conn:
            row = conn.execute(
                select(backup_artifacts).where(backup_artifacts.c.id == backup_id.value)
            ).one_or_none()
        return self._to_domain(row) if row is not None else None

    def list_all(self) -> list[BackupArtifact]:
        with self._db.connect() as conn:
            rows = conn.execute(
                select(backup_artifacts).order_by(backup_artifacts.c.created_at.desc())
            ).all()
        return [self._to_domain(row) for row in rows]

    def delete(self, backup_id: BackupId) -> None:
        with self._db.transaction() as conn:
            conn.execute(delete(backup_artifacts).where(backup_artifacts.c.id == backup_id.value))

    def last_successful_at(self) -> datetime | None:
        with self._db.connect() as conn:
            result = conn.execute(select(func.max(backup_artifacts.c.created_at))).scalar()
        return _aware(result)
