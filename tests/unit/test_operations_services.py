"""operations 서비스 테스트 — 백업 · 복구 · 헬스체크 · 오류 처리 · 종료 (S16)."""

from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phc.operations.adapters.console_notification import ConsoleNotificationChannel
from phc.operations.adapters.in_memory import (
    InMemoryAlertStore,
    InMemoryAuditTrail,
    InMemoryBackupStore,
)
from phc.operations.domain.alert import Alert, AlertId, AlertKind, AlertSeverity
from phc.operations.domain.audit import AuditEventType
from phc.operations.domain.backup import BackupArtifact, BackupId
from phc.operations.ports.audit import AuditFilter
from phc.operations.services.alerting import AlertDispatcher
from phc.operations.services.backup import (
    BackupRunner,
    BackupScheduler,
    RestoreRunner,
    is_same_volume,
)
from phc.operations.services.health import ComponentHealth, HealthProbe, HealthState
from phc.operations.services.metrics import MetricName, MetricsRegistry
from phc.operations.services.shutdown import GlobalErrorHandler, ShutdownCoordinator
from phc.shared import (
    AuthzError,
    CipherPurpose,
    DomainError,
    UndeterminedError,
    ValidationError,
)
from phc.shared.ports.clock import FixedClock

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SCHEMA = "0001"


# ---------------------------------------------------------------------------
# 테스트 대역
# ---------------------------------------------------------------------------
class FakeCipher:
    """XOR 기반 가짜 암호화. 암·복호화가 짝을 이루는지만 확인합니다."""

    KEY = 0x5A

    def encrypt(self, plain: bytes, purpose: CipherPurpose) -> bytes:
        return bytes(b ^ self.KEY for b in plain)

    def decrypt(self, cipher: bytes, purpose: CipherPurpose) -> bytes:
        return bytes(b ^ self.KEY for b in cipher)


class FakeSnapshotSource:
    def __init__(self, *, payload: bytes = b"snapshot-data", fail: bool = False) -> None:
        self._payload = payload
        self._fail = fail
        self.restored: bytes | None = None

    def create_snapshot(self) -> bytes:
        if self._fail:
            raise OSError("디스크 오류")
        return self._payload

    def restore_snapshot(self, data: bytes) -> None:
        self.restored = data

    @property
    def schema_version(self) -> str:
        return SCHEMA


# ---------------------------------------------------------------------------
# 동일 볼륨 판정 (RSK-06)
# ---------------------------------------------------------------------------
class TestSameVolumeDetection:
    def test_같은_드라이브면_같은_볼륨으로_판정한다(self, tmp_path: Path) -> None:
        assert is_same_volume(tmp_path / "a", tmp_path / "b")

    def test_판정_불가_시_보수적으로_같다고_본다(self) -> None:
        """경고를 놓치는 것보다 불필요하게 띄우는 편이 낫습니다."""
        assert is_same_volume(Path("\x00invalid"), Path("\x00invalid"))


# ---------------------------------------------------------------------------
# 백업 스케줄러 — 미실행 보충
# ---------------------------------------------------------------------------
class TestBackupScheduler:
    def test_백업이_한_번도_없으면_실행_대상이다(self) -> None:
        scheduler = BackupScheduler(store=InMemoryBackupStore(), clock=FixedClock(NOW))
        assert scheduler.is_due()

    def test_주기를_넘겼으면_실행_대상이다(self) -> None:
        """⭐ PC 를 꺼 두어 예정 시각을 놓친 경우를 보충합니다."""
        store = InMemoryBackupStore()
        store.save(_artifact(created_at=NOW - timedelta(days=2)))
        assert BackupScheduler(store=store, clock=FixedClock(NOW)).is_due()

    def test_방금_백업했으면_실행_대상이_아니다(self) -> None:
        store = InMemoryBackupStore()
        store.save(_artifact(created_at=NOW - timedelta(minutes=5)))
        assert not BackupScheduler(store=store, clock=FixedClock(NOW)).is_due()

    def test_다음_실행_시각은_항상_미래다(self) -> None:
        scheduler = BackupScheduler(store=InMemoryBackupStore(), clock=FixedClock(NOW))
        assert scheduler.next_run() > NOW


def _artifact(*, created_at: datetime, checksum: str = "x") -> BackupArtifact:
    return BackupArtifact(
        id=BackupId.generate(),
        created_at=created_at,
        artifact_ref="memory://artifact",
        size_bytes=1,
        checksum=checksum,
        cipher_key_ref="backup",
        schema_version=SCHEMA,
    )


# ---------------------------------------------------------------------------
# 백업 실행
# ---------------------------------------------------------------------------
class TestBackupRunner:
    def _runner(
        self, tmp_path: Path, *, fail: bool = False
    ) -> tuple[BackupRunner, InMemoryAuditTrail, InMemoryAlertStore, InMemoryBackupStore]:
        audit = InMemoryAuditTrail()
        alert_store = InMemoryAlertStore()
        backup_store = InMemoryBackupStore()
        clock = FixedClock(NOW)
        runner = BackupRunner(
            source=FakeSnapshotSource(fail=fail),
            store=backup_store,
            cipher=FakeCipher(),
            clock=clock,
            audit=audit,
            alerts=AlertDispatcher(store=alert_store, channels=[], clock=clock),
            backup_dir=tmp_path / "backups",
            data_dir=tmp_path / "data",
        )
        return runner, audit, alert_store, backup_store

    def test_성공하면_암호화된_파일과_메타데이터가_남는다(self, tmp_path: Path) -> None:
        runner, audit, _, store = self._runner(tmp_path)

        artifact = runner.run()

        written = Path(artifact.artifact_ref).read_bytes()
        assert written != b"snapshot-data"  # 암호화됨
        assert FakeCipher().decrypt(written, CipherPurpose.BACKUP) == b"snapshot-data"
        assert store.get(artifact.id) is not None
        assert audit.count_since(AuditEventType.BACKUP_SUCCEEDED, NOW) == 1

    def test_파일명에_사용자_정보가_드러나지_않는다(self, tmp_path: Path) -> None:
        runner, _, _, _ = self._runner(tmp_path)
        name = Path(runner.run().artifact_ref).name
        assert name.startswith("phc-")
        assert name.endswith(".bak.enc")

    def test_실패하면_감사와_알림이_모두_남고_예외가_전파된다(self, tmp_path: Path) -> None:
        """⭐ 백업 실패는 조용히 묻히지 않습니다 (BR-BK-05)."""
        runner, audit, alert_store, _ = self._runner(tmp_path, fail=True)

        with pytest.raises(OSError, match="디스크 오류"):
            runner.run()

        assert audit.count_since(AuditEventType.BACKUP_FAILED, NOW) == 1
        assert alert_store.list_open()[0].kind is AlertKind.BACKUP_FAILURE

    def test_백업이_같은_볼륨에_있으면_알린다(self, tmp_path: Path) -> None:
        runner, _, _, _ = self._runner(tmp_path)
        assert runner.is_on_same_volume


# ---------------------------------------------------------------------------
# 복원 — fail closed
# ---------------------------------------------------------------------------
class TestRestoreRunner:
    def _setup(self, tmp_path: Path) -> tuple[RestoreRunner, FakeSnapshotSource, BackupId]:
        source = FakeSnapshotSource()
        store = InMemoryBackupStore()
        clock = FixedClock(NOW)

        encrypted = FakeCipher().encrypt(b"snapshot-data", CipherPurpose.BACKUP)
        path = tmp_path / "b.enc"
        path.write_bytes(encrypted)

        artifact = BackupArtifact(
            id=BackupId.generate(),
            created_at=NOW,
            artifact_ref=str(path),
            size_bytes=len(encrypted),
            checksum=hashlib.sha256(encrypted).hexdigest(),
            cipher_key_ref="backup",
            schema_version=SCHEMA,
        )
        store.save(artifact)

        runner = RestoreRunner(
            source=source,
            store=store,
            cipher=FakeCipher(),
            clock=clock,
            audit=InMemoryAuditTrail(),
            known_schema_order=[SCHEMA, "0002"],
        )
        return runner, source, artifact.id

    def test_정상_백업은_복원된다(self, tmp_path: Path) -> None:
        runner, source, backup_id = self._setup(tmp_path)
        report = runner.restore(backup_id)

        assert report.verified
        assert source.restored == b"snapshot-data"

    def test_체크섬이_어긋나면_복원하지_않는다(self, tmp_path: Path) -> None:
        """⛔ 손상되었을지 모르는 백업으로 덮어쓰는 것은 되돌릴 수 없습니다."""
        runner, source, backup_id = self._setup(tmp_path)
        artifact = runner._store.get(backup_id)  # 테스트에서 내부 상태 조작
        assert artifact is not None
        Path(artifact.artifact_ref).write_bytes(b"tampered")

        assert runner.verify(backup_id) is False
        with pytest.raises(UndeterminedError):
            runner.restore(backup_id)
        assert source.restored is None

    def test_존재하지_않는_백업은_거부한다(self, tmp_path: Path) -> None:
        runner, _, _ = self._setup(tmp_path)
        with pytest.raises(DomainError, match="백업을 찾을 수 없습니다"):
            runner.restore(BackupId("nope"))

    def test_앱보다_최신_스키마_백업은_복원하지_않는다(self) -> None:
        """구버전 앱이 신버전 백업을 되돌리면 무엇이 깨질지 알 수 없습니다."""
        newer = BackupArtifact(
            id=BackupId("b1"),
            created_at=NOW,
            artifact_ref="memory://artifact",
            size_bytes=1,
            checksum="x",
            cipher_key_ref="backup",
            schema_version="0002",
        )
        assert not newer.is_restorable_onto("0001", ["0001", "0002"])
        assert newer.is_restorable_onto("0002", ["0001", "0002"])

    def test_리허설이_오래되면_재검증_대상이_된다(self) -> None:
        artifact = _artifact(created_at=NOW)
        assert artifact.needs_reverification(NOW, timedelta(days=100))


# ---------------------------------------------------------------------------
# 헬스체크
# ---------------------------------------------------------------------------
class TestHealthProbe:
    def test_얕은_검사는_항상_UP_이다(self) -> None:
        assert HealthProbe(clock=FixedClock(NOW)).shallow().state is HealthState.UP

    def test_모든_항목이_정상이면_UP(self) -> None:
        probe = HealthProbe(clock=FixedClock(NOW))
        probe.register_deep_check("db", lambda: ComponentHealth("db", HealthState.UP))

        status = probe.deep()
        assert status.state is HealthState.UP
        assert status.is_healthy

    def test_한_항목이_DOWN_이면_전체가_DOWN(self) -> None:
        probe = HealthProbe(clock=FixedClock(NOW))
        probe.register_deep_check("db", lambda: ComponentHealth("db", HealthState.UP))
        probe.register_deep_check("keys", lambda: ComponentHealth("keys", HealthState.DOWN))

        assert probe.deep().state is HealthState.DOWN

    def test_DEGRADED_는_DOWN_보다_약하게_집계된다(self) -> None:
        probe = HealthProbe(clock=FixedClock(NOW))
        probe.register_deep_check("db", lambda: ComponentHealth("db", HealthState.DEGRADED))

        assert probe.deep().state is HealthState.DEGRADED

    def test_검사가_예외를_던져도_전체_응답은_반환된다(self) -> None:
        """헬스체크가 걸려서 상태를 알 수 없으면 무용합니다."""

        def boom() -> ComponentHealth:
            raise RuntimeError("연결 실패")

        probe = HealthProbe(clock=FixedClock(NOW))
        probe.register_deep_check("db", boom)

        status = probe.deep()
        assert status.state is HealthState.DOWN
        assert status.components[0].detail == "RuntimeError"


# ---------------------------------------------------------------------------
# 전역 오류 처리
# ---------------------------------------------------------------------------
class TestGlobalErrorHandler:
    def _handler(self) -> tuple[GlobalErrorHandler, MetricsRegistry]:
        metrics = MetricsRegistry()
        return GlobalErrorHandler(metrics=metrics), metrics

    def test_도메인_오류는_안전_문구를_그대로_쓴다(self) -> None:
        handler, _ = self._handler()
        response = handler.handle(ValidationError("사용자명이 너무 짧습니다."))

        assert response.status_code == 400
        assert response.message == "사용자명이 너무 짧습니다."

    def test_인가_거부는_403_이다(self) -> None:
        handler, _ = self._handler()
        assert handler.handle(AuthzError()).status_code == 403

    def test_판정_불가는_503_이다(self) -> None:
        handler, _ = self._handler()
        assert handler.handle(UndeterminedError("throttle")).status_code == 503

    def test_예상하지_못한_예외는_내부_정보를_노출하지_않는다(self) -> None:
        """⚠ 스택·경로·프레임워크 버전이 응답에 없어야 합니다 (NFR-1A-26)."""
        handler, metrics = self._handler()

        response = handler.handle(RuntimeError("C:\\secret\\path\\module.py 에서 실패"))

        assert response.status_code == 500
        assert response.message == GlobalErrorHandler.GENERIC_MESSAGE
        assert "secret" not in response.message
        assert "RuntimeError" not in response.message
        assert metrics.snapshot().counters[MetricName.ERROR_UNHANDLED] == 1


# ---------------------------------------------------------------------------
# 우아한 종료
# ---------------------------------------------------------------------------
class TestShutdownCoordinator:
    def test_등록된_순서대로_정리한다(self) -> None:
        order: list[str] = []
        coordinator = ShutdownCoordinator()
        coordinator.register_web_stop(lambda: order.append("web"))
        coordinator.register_worker(
            lambda: order.append("worker"), threading.Thread(target=lambda: None)
        )
        coordinator.register_db_close(lambda: order.append("db"))

        coordinator.shutdown()

        assert order == ["web", "worker", "db"]

    def test_한_단계가_실패해도_나머지_정리는_계속된다(self) -> None:
        order: list[str] = []
        coordinator = ShutdownCoordinator()
        coordinator.register_web_stop(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        coordinator.register_db_close(lambda: order.append("db"))

        coordinator.shutdown()

        assert order == ["db"]


# ---------------------------------------------------------------------------
# 콘솔 알림 채널
# ---------------------------------------------------------------------------
class TestConsoleNotificationChannel:
    @pytest.mark.parametrize(
        "severity", [AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
    )
    def test_등급별로_전달된다(self, severity: AlertSeverity) -> None:
        channel = ConsoleNotificationChannel()
        alert = Alert(
            id=AlertId.generate(),
            kind=AlertKind.AUTHZ_VIOLATION,
            severity=severity,
            raised_at=NOW,
            summary="테스트",
        )
        channel.send(alert)  # 예외 없이 처리되면 통과

    def test_채널_이름을_노출한다(self) -> None:
        assert ConsoleNotificationChannel().name == "console"


# ---------------------------------------------------------------------------
# 감사 조회
# ---------------------------------------------------------------------------
class TestAuditQuery:
    def test_기간과_종류로_거를_수_있다(self) -> None:
        from phc.operations.domain.audit import AuditEntry, AuditOutcome

        trail = InMemoryAuditTrail()
        trail.append(AuditEntry(AuditEventType.LOGIN_SUCCEEDED, AuditOutcome.SUCCEEDED, NOW))
        trail.append(AuditEntry(AuditEventType.AUTHZ_DENIED, AuditOutcome.DENIED, NOW))

        denied = trail.query(AuditFilter(event_types=frozenset({AuditEventType.AUTHZ_DENIED})))

        assert len(denied) == 1
        assert denied[0].event_type is AuditEventType.AUTHZ_DENIED
        assert trail.max_seq() == 2
