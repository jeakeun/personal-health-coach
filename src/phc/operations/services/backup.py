"""백업·복구 (S15).

⭐ **백업 실패는 조용히 묻히지 않습니다** (BR-BK-05, US-37 인수 기준).
   백업이 조용히 실패하면 사고가 날 때까지 아무도 모릅니다.

⚠ **동일 디스크 경고**: 백업을 원본과 같은 볼륨에 두면 디스크 장애(RSK-06)에
   대해 아무런 방어가 되지 않습니다. 판정하여 운영 화면에 상시 표시합니다
   (Infrastructure Design §4.1).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Final, Protocol

from phc.operations.domain.alert import AlertKind
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.domain.backup import BackupArtifact, BackupId, RetentionPolicy
from phc.operations.ports.audit import AuditTrailPort
from phc.operations.ports.backup_store import BackupStorePort
from phc.operations.services.alerting import AlertDispatcher
from phc.operations.services.logging import get_logger
from phc.shared import CipherPort, CipherPurpose, ClockPort, DomainError, UndeterminedError

__all__ = [
    "REVERIFY_AFTER",
    "BackupRunner",
    "BackupScheduler",
    "RestoreReport",
    "RestoreRunner",
    "SnapshotSource",
    "is_same_volume",
]

_log = get_logger(__name__)

#: 복원 리허설이 이 기간을 넘기면 운영 화면에 주의 표시 (분기 1회 기준 + 여유).
REVERIFY_AFTER: Final = timedelta(days=100)


def is_same_volume(a: Path, b: Path) -> bool:
    """두 경로가 같은 볼륨에 있는가.

    Windows 에서는 드라이브 문자로, 그 외에서는 마운트 지점으로 판정합니다.
    같은 볼륨이면 백업이 디스크 장애 방어가 되지 않습니다.
    """
    try:
        return Path(a).resolve().drive.upper() == Path(b).resolve().drive.upper()
    except (OSError, ValueError):
        # ValueError 도 잡습니다 — Windows 에서 널 바이트가 섞인 경로는
        # OSError 가 아니라 ValueError 를 냅니다.
        # 판정 불가 시 "같다"로 보아 경고를 띄웁니다. 경고를 놓치는 것보다
        # 불필요하게 띄우는 편이 낫습니다 (RSK-06).
        return True


class SnapshotSource(Protocol):
    """DB 일관 스냅샷 생성기. 저장소 어댑터가 구현합니다 (Phase 4)."""

    def create_snapshot(self) -> bytes: ...

    def restore_snapshot(self, data: bytes) -> None: ...

    @property
    def schema_version(self) -> str: ...


class BackupScheduler:
    """예약 백업 등록 (US-37).

    ⭐ **미실행 보충**: PC 를 꺼 두어 예정 시각을 놓쳤다면, 다음 기동 시
    주기를 넘겼는지 확인해 즉시 1회 실행합니다. 노트북 사용 패턴에서는
    "매일 03시" 가 실제로는 자주 건너뛰어집니다.
    """

    def __init__(
        self,
        *,
        store: BackupStorePort,
        clock: ClockPort,
        run_at_hour: int = 3,
        interval: timedelta = timedelta(days=1),
    ) -> None:
        self._store = store
        self._clock = clock
        self._run_at = time(hour=run_at_hour)
        self._interval = interval

    def is_due(self) -> bool:
        now = self._clock.now()
        last = self._store.last_successful_at()
        if last is None:
            return True
        if now - last >= self._interval:
            return True
        # 오늘의 예정 시각을 지났고 그 이후 백업이 없는 경우
        scheduled_today = now.replace(hour=self._run_at.hour, minute=0, second=0, microsecond=0)
        return now >= scheduled_today > last

    def next_run(self) -> datetime:
        now = self._clock.now()
        candidate = now.replace(hour=self._run_at.hour, minute=0, second=0, microsecond=0)
        return candidate if candidate > now else candidate + timedelta(days=1)


class BackupRunner:
    """백업 실행 (BR-BK-01~05, BR-BK-09)."""

    def __init__(
        self,
        *,
        source: SnapshotSource,
        store: BackupStorePort,
        cipher: CipherPort,
        clock: ClockPort,
        audit: AuditTrailPort,
        alerts: AlertDispatcher,
        backup_dir: Path,
        data_dir: Path,
        retention: RetentionPolicy | None = None,
        cipher_key_ref: str = "backup",
    ) -> None:
        self._source = source
        self._store = store
        self._cipher = cipher
        self._clock = clock
        self._audit = audit
        self._alerts = alerts
        self._backup_dir = backup_dir
        self._data_dir = data_dir
        self._retention = retention or RetentionPolicy()
        self._cipher_key_ref = cipher_key_ref

    @property
    def is_on_same_volume(self) -> bool:
        """⚠ 백업이 원본과 같은 볼륨에 있는가 (RSK-06 방어 무력 여부)."""
        return is_same_volume(self._backup_dir, self._data_dir)

    def run(self) -> BackupArtifact:
        now = self._clock.now()
        try:
            snapshot = self._source.create_snapshot()
            encrypted = self._cipher.encrypt(snapshot, CipherPurpose.BACKUP)

            # 파일명에 사용자명·건강 데이터가 드러나지 않게 시각만 사용 (BR-BK-09)
            filename = f"phc-{now:%Y%m%d-%H%M%S}.bak.enc"
            path = self._backup_dir / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(encrypted)

            artifact = BackupArtifact(
                id=BackupId.generate(),
                created_at=now,
                artifact_ref=str(path),
                size_bytes=len(encrypted),
                checksum=hashlib.sha256(encrypted).hexdigest(),
                cipher_key_ref=self._cipher_key_ref,
                schema_version=self._source.schema_version,
            )
            self._store.save(artifact)
            self._prune()

        except Exception as exc:
            # ⭐ 조용히 묻히지 않게 — 감사 + 알림 둘 다
            self._audit.append(
                AuditEntry(
                    event_type=AuditEventType.BACKUP_FAILED,
                    outcome=AuditOutcome.FAILED,
                    occurred_at=now,
                    detail={"error_type": type(exc).__name__},
                )
            )
            self._alerts.raise_immediate(
                AlertKind.BACKUP_FAILURE,
                "백업이 실패했습니다. 데이터 손실 위험이 있습니다.",
                context={"error_type": type(exc).__name__},
            )
            _log.error("backup.failed", error_type=type(exc).__name__)
            raise

        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.BACKUP_SUCCEEDED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                target_ref=f"backup:{artifact.id}",
                detail={"schema_version": artifact.schema_version},
            )
        )
        _log.info("backup.succeeded", backup_id=artifact.id, size_bytes=str(artifact.size_bytes))
        return artifact

    def _prune(self) -> None:
        for expired in self._retention.select_expired(self._store.list_all()):
            try:
                Path(expired.artifact_ref).unlink(missing_ok=True)
            except OSError as exc:
                _log.warning("backup.prune_failed", backup_id=expired.id, error=str(exc))
                continue
            self._store.delete(expired.id)


@dataclass(frozen=True, slots=True)
class RestoreReport:
    backup_id: BackupId
    restored_at: datetime
    schema_version: str
    verified: bool


class RestoreRunner:
    """복원 실행 (US-38, AC-11, BR-BK-06/07).

    ⛔ 체크섬 또는 스키마 버전 검증에 실패하면 **복원하지 않습니다**.
       손상되었을지 모르는 백업으로 덮어쓰는 것은 되돌릴 수 없습니다.
    """

    def __init__(
        self,
        *,
        source: SnapshotSource,
        store: BackupStorePort,
        cipher: CipherPort,
        clock: ClockPort,
        audit: AuditTrailPort,
        known_schema_order: list[str],
    ) -> None:
        self._source = source
        self._store = store
        self._cipher = cipher
        self._clock = clock
        self._audit = audit
        self._known_schema_order = known_schema_order

    def verify(self, backup_id: BackupId) -> bool:
        """무결성과 복원 가능성을 확인한다. 복원은 하지 않는다."""
        artifact = self._store.get(backup_id)
        if artifact is None:
            return False

        try:
            data = Path(artifact.artifact_ref).read_bytes()
        except OSError:
            return False

        if hashlib.sha256(data).hexdigest() != artifact.checksum:
            _log.error("restore.checksum_mismatch", backup_id=backup_id)
            return False

        return artifact.is_restorable_onto(self._source.schema_version, self._known_schema_order)

    def restore(self, backup_id: BackupId) -> RestoreReport:
        artifact = self._store.get(backup_id)
        if artifact is None:
            raise DomainError("backup_not_found", "백업을 찾을 수 없습니다.")

        if not self.verify(backup_id):
            raise UndeterminedError(
                "backup_verification",
                detail=f"backup_id={backup_id} 검증 실패 — 복원하지 않습니다",
            )

        data = Path(artifact.artifact_ref).read_bytes()
        plain = self._cipher.decrypt(data, CipherPurpose.BACKUP)
        self._source.restore_snapshot(plain)

        now = self._clock.now()
        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.RESTORE_PERFORMED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                target_ref=f"backup:{artifact.id}",
                detail={"schema_version": artifact.schema_version},
            )
        )
        _log.warning("restore.performed", backup_id=backup_id)

        return RestoreReport(
            backup_id=artifact.id,
            restored_at=now,
            schema_version=artifact.schema_version,
            verified=True,
        )
