"""operations 모듈 단위 테스트 (S16)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phc.operations.adapters.in_memory import (
    InMemoryAlertStore,
    InMemoryAuditTrail,
    InMemoryJobQueue,
)
from phc.operations.domain.alert import AlertKind
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.domain.backup import BackupArtifact, BackupId, RetentionPolicy
from phc.operations.domain.job import Job, JobKind, JobSpec, JobState, WorkerId
from phc.operations.ports.audit import AuditFilter
from phc.operations.ports.job_queue import JobHandlerRegistry, RetryableJobError
from phc.operations.services.alerting import AlertDispatcher
from phc.operations.services.logging import RedactionError, RedactionProcessor
from phc.operations.services.metrics import MetricsRegistry
from phc.operations.services.worker import JobReaper, JobWorker
from phc.shared import (
    AuthContext,
    OwnerScope,
    PasswordHash,
    Role,
    SecretStr,
    SessionToken,
    UserId,
)
from phc.shared.ports.clock import FixedClock

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def scope_for(owner: str = "owner-1") -> OwnerScope:
    return OwnerScope.for_subject(AuthContext(UserId(owner), Role.USER))


# ---------------------------------------------------------------------------
# L-07 RedactionProcessor — 런타임 2차 방어
# ---------------------------------------------------------------------------
class TestRedactionProcessor:
    @pytest.mark.parametrize(
        "value",
        [SecretStr("hunter2"), PasswordHash("$argon2id$..."), SessionToken("tok")],
    )
    def test_민감_타입은_strict_모드에서_예외를_던진다(self, value: object) -> None:
        processor = RedactionProcessor(strict=True)
        with pytest.raises(RedactionError):
            processor(None, "info", {"event": "x", "value": value})

    def test_민감_타입은_운영_모드에서_대체된다(self) -> None:
        processor = RedactionProcessor(strict=False)
        out = processor(None, "info", {"event": "x", "value": SecretStr("hunter2")})
        assert out["value"] == "<redacted>"
        assert "hunter2" not in str(out)

    def test_키_이름으로도_차단한다(self) -> None:
        """⭐ 평문 str 로 넘기면 타입 방어를 빠져나가므로 키 이름을 함께 본다."""
        processor = RedactionProcessor(strict=True)
        with pytest.raises(RedactionError):
            processor(None, "info", {"event": "login", "password": "plain-text"})

    def test_Redactable_은_안전한_표현으로_바뀐다(self) -> None:
        processor = RedactionProcessor(strict=True)
        uid = UserId("u-1")
        out = processor(None, "info", {"event": "x", "user_id": uid})
        assert out["user_id"] == "u-1"

    def test_일반_값은_그대로_통과한다(self) -> None:
        processor = RedactionProcessor(strict=True)
        out = processor(None, "info", {"event": "x", "count": 3})
        assert out["count"] == 3


# ---------------------------------------------------------------------------
# 감사 — append-only
# ---------------------------------------------------------------------------
class TestAuditTrail:
    def test_갱신_삭제_메서드가_존재하지_않는다(self) -> None:
        """⭐ NFR-10 — 구현 누락이 아니라 인터페이스 부재."""
        trail = InMemoryAuditTrail()
        assert not hasattr(trail, "update")
        assert not hasattr(trail, "delete")

    def test_seq_가_결번_없이_증가한다(self) -> None:
        trail = InMemoryAuditTrail()
        for _ in range(5):
            trail.append(
                AuditEntry(
                    event_type=AuditEventType.LOGIN_SUCCEEDED,
                    outcome=AuditOutcome.SUCCEEDED,
                    occurred_at=NOW,
                )
            )
        seqs = [e.seq for e in trail.query(AuditFilter(limit=10))]
        assert sorted(s for s in seqs if s is not None) == [1, 2, 3, 4, 5]

    def test_인가_거부는_알림_대상이다(self) -> None:
        entry = AuditEntry(
            event_type=AuditEventType.AUTHZ_DENIED,
            outcome=AuditOutcome.DENIED,
            occurred_at=NOW,
        )
        assert entry.is_alert_worthy

    def test_로그인_성공은_알림_대상이_아니다(self) -> None:
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCEEDED,
            outcome=AuditOutcome.SUCCEEDED,
            occurred_at=NOW,
        )
        assert not entry.is_alert_worthy


# ---------------------------------------------------------------------------
# 작업 큐 — 예시 기반 (속성 테스트를 보완, PBT-10)
# ---------------------------------------------------------------------------
class TestJobQueue:
    def test_재시도_가능_실패는_백오프_후_다시_대기한다(self) -> None:
        job = Job.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)
        job = job.claim(WorkerId("w1"), now=NOW)
        job = job.fail(now=NOW, reason="io", retryable=True)

        assert job.state is JobState.PENDING
        assert job.attempts == 1
        assert job.next_attempt_at == NOW + timedelta(minutes=1)

    def test_재시도_불가_실패는_즉시_종료된다(self) -> None:
        """같은 입력으로 다시 시도해도 결과가 같으므로 재시도하지 않는다."""
        job = Job.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)
        job = job.claim(WorkerId("w1"), now=NOW)
        job = job.fail(now=NOW, reason="bad format", retryable=False)

        assert job.state is JobState.FAILED
        assert job.attempts == 1

    def test_최대_시도_횟수에_도달하면_실패로_끝난다(self) -> None:
        job = Job.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for(), max_attempts=3), now=NOW)
        now = NOW
        for _ in range(3):
            job = job.claim(WorkerId("w1"), now=now)
            job = job.fail(now=now, reason="io", retryable=True)
            now = job.next_attempt_at or now + timedelta(minutes=10)

        assert job.state is JobState.FAILED
        assert job.attempts == 3

    def test_회수는_재시도_횟수를_소모하지_않는다(self) -> None:
        """⭐ 워커 사망은 작업의 실패가 아니다 (BR-JQ-04)."""
        job = Job.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)
        job = job.claim(WorkerId("w1"), now=NOW)
        later = NOW + timedelta(minutes=6)

        assert job.is_stale(later, timedelta(minutes=5))
        reaped = job.reap(now=later)

        assert reaped.state is JobState.PENDING
        assert reaped.attempts == 0

    def test_백오프가_지수적으로_늘어난다(self) -> None:
        job = Job.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for(), max_attempts=5), now=NOW)
        delays = []
        now = NOW
        for _ in range(3):
            job = job.claim(WorkerId("w1"), now=now)
            job = job.fail(now=now, reason="io", retryable=True)
            assert job.next_attempt_at is not None
            delays.append(job.next_attempt_at - now)
            now = job.next_attempt_at

        assert delays == [timedelta(minutes=1), timedelta(minutes=2), timedelta(minutes=4)]

    def test_두_워커가_같은_작업을_점유하지_않는다(self) -> None:
        queue = InMemoryJobQueue()
        queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)

        first = queue.claim(WorkerId("w1"), now=NOW)
        second = queue.claim(WorkerId("w2"), now=NOW)

        assert first is not None
        assert second is None


# ---------------------------------------------------------------------------
# 워커
# ---------------------------------------------------------------------------
class _RecordingHandler:
    def __init__(self, *, fail_with: Exception | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._fail_with = fail_with

    @property
    def kind(self) -> JobKind:
        return JobKind.BACKUP

    def execute(self, job: Job, scope: OwnerScope, progress: object) -> str | None:
        self.calls.append((job.id.value, scope.owner_id.value))
        if self._fail_with is not None:
            raise self._fail_with
        return "result-ref"


class TestJobWorker:
    def _worker(self, handler: object) -> tuple[JobWorker, InMemoryJobQueue, FixedClock]:
        queue = InMemoryJobQueue()
        registry = JobHandlerRegistry()
        registry.register(handler)  # type: ignore[arg-type]
        clock = FixedClock(NOW)
        worker = JobWorker(queue=queue, registry=registry, clock=clock, worker_id=WorkerId("w1"))
        return worker, queue, clock

    def test_소유자_스코프가_작업_레코드로부터_재구성된다(self) -> None:
        """⭐ 경계 B — 작업 큐를 경유해 타인 데이터에 도달하지 않는다."""
        handler = _RecordingHandler()
        worker, queue, _ = self._worker(handler)
        queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for("alice")), now=NOW)

        assert worker.run_once()
        assert handler.calls[0][1] == "alice"

    def test_처리할_작업이_없으면_False(self) -> None:
        worker, _, _ = self._worker(_RecordingHandler())
        assert worker.run_once() is False

    def test_성공하면_SUCCEEDED_가_된다(self) -> None:
        worker, queue, _ = self._worker(_RecordingHandler())
        job = queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)

        worker.run_once()
        stored = queue.get(job.id)

        assert stored is not None
        assert stored.state is JobState.SUCCEEDED
        assert stored.result_ref == "result-ref"

    def test_재시도_가능_실패는_다시_대기_상태가_된다(self) -> None:
        worker, queue, _ = self._worker(_RecordingHandler(fail_with=RetryableJobError("io")))
        job = queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)

        worker.run_once()
        stored = queue.get(job.id)

        assert stored is not None
        assert stored.state is JobState.PENDING
        assert stored.attempts == 1

    def test_등록되지_않은_종류는_재시도하지_않는다(self) -> None:
        queue = InMemoryJobQueue()
        clock = FixedClock(NOW)
        worker = JobWorker(
            queue=queue,
            registry=JobHandlerRegistry(),  # 핸들러 없음
            clock=clock,
            worker_id=WorkerId("w1"),
        )
        job = queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)

        worker.run_once()
        stored = queue.get(job.id)

        assert stored is not None
        assert stored.state is JobState.FAILED


class TestJobReaper:
    def test_heartbeat_만료_작업을_회수한다(self) -> None:
        queue = InMemoryJobQueue()
        clock = FixedClock(NOW)
        job = queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)
        queue.save(job.claim(WorkerId("dead-worker"), now=NOW))

        clock.advance(timedelta(minutes=6))
        reaper = JobReaper(queue=queue, clock=clock)

        assert reaper.reap_stale() == 1
        stored = queue.get(job.id)
        assert stored is not None
        assert stored.state is JobState.PENDING
        assert stored.claimed_by is None

    def test_살아있는_작업은_회수하지_않는다(self) -> None:
        queue = InMemoryJobQueue()
        clock = FixedClock(NOW)
        job = queue.enqueue(JobSpec.for_scope(JobKind.BACKUP, scope_for()), now=NOW)
        queue.save(job.claim(WorkerId("w1"), now=NOW))

        clock.advance(timedelta(minutes=1))
        assert JobReaper(queue=queue, clock=clock).reap_stale() == 0


# ---------------------------------------------------------------------------
# 알림
# ---------------------------------------------------------------------------
class TestAlertDispatcher:
    def _dispatcher(self) -> tuple[AlertDispatcher, InMemoryAlertStore, FixedClock]:
        store = InMemoryAlertStore()
        clock = FixedClock(NOW)
        return AlertDispatcher(store=store, channels=[], clock=clock), store, clock

    def test_인가_위반은_1회로_알림이_발생한다(self) -> None:
        dispatcher, store, _ = self._dispatcher()
        alert = dispatcher.raise_immediate(AlertKind.AUTHZ_VIOLATION, "인가 거부")

        assert alert is not None
        assert store.list_open()[0].kind is AlertKind.AUTHZ_VIOLATION

    def test_로그인_실패는_임계_미만이면_알리지_않는다(self) -> None:
        dispatcher, _, _ = self._dispatcher()
        result = dispatcher.raise_if_over_threshold(
            AlertKind.LOGIN_FAILURE_BURST_ACCOUNT, 9, summary="반복 실패"
        )
        assert result is None

    def test_로그인_실패는_임계_이상이면_알린다(self) -> None:
        dispatcher, _, _ = self._dispatcher()
        result = dispatcher.raise_if_over_threshold(
            AlertKind.LOGIN_FAILURE_BURST_ACCOUNT, 10, summary="반복 실패"
        )
        assert result is not None
        assert result.context["occurrences"] == "10"

    def test_즉시_알림_대상이_아닌_종류는_거부한다(self) -> None:
        dispatcher, _, _ = self._dispatcher()
        with pytest.raises(ValueError, match="즉시 알림 대상이 아닙니다"):
            dispatcher.raise_immediate(AlertKind.LOGIN_FAILURE_BURST_ACCOUNT, "x")


# ---------------------------------------------------------------------------
# 백업 보관 정책
# ---------------------------------------------------------------------------
class TestRetentionPolicy:
    @staticmethod
    def _artifact(days_ago: int) -> BackupArtifact:
        return BackupArtifact(
            id=BackupId(f"b{days_ago}"),
            created_at=NOW - timedelta(days=days_ago),
            artifact_ref=f"/backups/b{days_ago}",
            size_bytes=1,
            checksum="x",
            cipher_key_ref="backup",
            schema_version="0001",
        )

    def test_최근_일간_백업은_보존된다(self) -> None:
        artifacts = [self._artifact(d) for d in range(0, 30)]
        expired = RetentionPolicy().select_expired(artifacts)
        expired_ids = {a.id for a in expired}

        for recent in range(7):
            assert BackupId(f"b{recent}") not in expired_ids

    def test_오래된_백업은_정리_대상이_된다(self) -> None:
        artifacts = [self._artifact(d) for d in range(0, 400)]
        expired = RetentionPolicy().select_expired(artifacts)

        assert len(expired) > 0
        # 일간 슬롯 7개는 최근 7일(0~6일 전)이므로, 정리 대상은 7일 전 이상입니다.
        # 경계값(정확히 7일 전)도 정리 대상이 될 수 있으므로 <= 로 비교합니다.
        assert all(a.created_at <= NOW - timedelta(days=7) for a in expired)

    def test_보존_대상이_정책_상한을_넘지_않는다(self) -> None:
        """일 7 + 주 4 + 월 3 = 최대 14개. 슬롯이 겹치면 그보다 적습니다."""
        artifacts = [self._artifact(d) for d in range(0, 400)]
        kept = len(artifacts) - len(RetentionPolicy().select_expired(artifacts))
        assert kept <= 14


# ---------------------------------------------------------------------------
# 메트릭
# ---------------------------------------------------------------------------
class TestMetricsRegistry:
    def test_카운터와_게이지와_히스토그램을_수집한다(self) -> None:
        registry = MetricsRegistry()
        registry.increment("login.success")
        registry.increment("login.success")
        registry.set_gauge("session.active", 3)
        for value in (10.0, 20.0, 30.0):
            registry.observe("password.hash.duration", value)

        snap = registry.snapshot()

        assert snap.counters["login.success"] == 2
        assert snap.gauges["session.active"] == 3
        assert snap.histograms["password.hash.duration"].count == 3
        assert snap.histograms["password.hash.duration"].max_value == 30.0

    def test_관측치가_상한을_넘으면_오래된_것을_버린다(self) -> None:
        registry = MetricsRegistry()
        for i in range(MetricsRegistry.MAX_OBSERVATIONS + 100):
            registry.observe("x", float(i))

        assert registry.snapshot().histograms["x"].count == MetricsRegistry.MAX_OBSERVATIONS
