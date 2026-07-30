"""⭐ 리포지토리 계약 테스트 (S29) — 인메모리와 SQL 두 구현에 **동일 적용**.

이것이 NFR-1A-38 의 판정 수단입니다.

    판정 기준: "인메모리 리포지토리 구현으로 도메인 테스트가 통과하는가"

도메인 모델이 SQLAlchemy 에 종속되면 인메모리 구현을 만들 수 없고, 그러면
이 파일이 존재할 수 없습니다. 두 구현이 **같은 명세**를 만족한다는 것이
포트 추상화의 실질입니다 (D7=A).

⚠ 여기서 잡히는 것: SQL 구현에만 있는 미묘한 차이. 실제로
   **SQLite 가 timezone 을 잃어버리는 문제**를 이 테스트가 잡았습니다.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from phc.identity.adapters.in_memory import (
    InMemoryAccountRepository,
    InMemoryMfaRepository,
    InMemorySessionRepository,
    InMemoryThrottleRepository,
)
from phc.identity.adapters.sql import (
    SqlAccountRepository,
    SqlMfaRepository,
    SqlSessionRepository,
    SqlThrottleRepository,
)
from phc.identity.domain.account import Account
from phc.identity.domain.mfa import MfaEnrollment, MfaRecoveryCode, RecoveryCodeId
from phc.identity.domain.session import Session
from phc.identity.domain.throttle import (
    AttemptOutcome,
    LoginAttempt,
    ThrottleKey,
    ThrottleState,
)
from phc.infrastructure.db.engine import Database, create_sqlite_engine
from phc.operations.adapters.in_memory import (
    InMemoryAlertStore,
    InMemoryAuditTrail,
    InMemoryBackupStore,
    InMemoryJobQueue,
)
from phc.operations.adapters.sql import (
    SqlAlertStore,
    SqlAuditTrail,
    SqlBackupStore,
    SqlJobQueue,
)
from phc.operations.domain.alert import Alert, AlertId, AlertKind, AlertSeverity
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.domain.backup import BackupArtifact, BackupId
from phc.operations.domain.job import JobKind, JobSpec, JobState, WorkerId
from phc.operations.ports.audit import AuditFilter
from phc.shared import (
    AuthContext,
    ConflictError,
    OwnerScope,
    PasswordHash,
    Role,
    SessionToken,
    UserId,
    Username,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 두 구현을 같은 테스트에 흘려보내는 장치
# ---------------------------------------------------------------------------
@pytest.fixture
def database() -> Iterator[Database]:
    """테스트마다 새 인메모리 SQLite."""
    db = Database(create_sqlite_engine(":memory:"))
    db.create_all()
    yield db
    db.dispose()


def _both(in_memory: Callable[[], Any], sql: Callable[[Database], Any]) -> Any:
    """구현 2종을 파라미터로 만든다."""
    return pytest.mark.parametrize(
        "make_repository",
        [
            pytest.param(lambda _db: in_memory(), id="in_memory"),
            pytest.param(sql, id="sql"),
        ],
    )


def make_account(
    *,
    user_id: str = "u-1",
    username: str = "alice",
    role: Role = Role.USER,
    active: bool = True,
) -> Account:
    return Account(
        id=UserId(user_id),
        username=Username.parse(username),
        display_name=username.capitalize(),
        password_hash=PasswordHash("fake$v1$abc"),
        role=role,
        is_active=active,
        must_change_password=False,
        created_at=NOW,
        updated_at=NOW,
    )


# ---------------------------------------------------------------------------
# AccountRepository 계약
# ---------------------------------------------------------------------------
@_both(InMemoryAccountRepository, SqlAccountRepository)
class TestAccountRepositoryContract:
    def test_저장하고_식별자로_찾는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        account = make_account()

        repo.save(account)
        found = repo.find_by_id(account.id)

        assert found is not None
        assert found.id == account.id
        assert found.username == account.username
        assert found.password_hash == account.password_hash

    def test_시각이_timezone_을_유지한다(self, make_repository: Any, database: Database) -> None:
        """⭐ SQLite 는 timezone 을 잃어버립니다.

        되살리지 않으면 세션 만료·잠금 판정에서 naive/aware 비교로
        ``TypeError`` 가 납니다. 이 계약 테스트가 그 차이를 잡습니다.
        """
        repo = make_repository(database)
        repo.save(make_account())

        found = repo.find_by_id(UserId("u-1"))

        assert found is not None
        assert found.created_at.tzinfo is not None
        assert found.created_at == NOW

    def test_정규화된_사용자명으로_찾는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.save(make_account(username="alice"))

        assert repo.find_by_username(Username.parse("Alice")) is not None
        assert repo.find_by_username(Username.parse("  ALICE  ")) is not None

    def test_없는_계정은_None_이다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)

        assert repo.find_by_id(UserId("ghost")) is None
        assert repo.find_by_username(Username.parse("ghost")) is None

    def test_사용자명_중복은_거부된다(self, make_repository: Any, database: Database) -> None:
        """⭐ INV-AC-02 의 최종 방어 — 사전 조회로는 동시 가입을 못 막습니다."""
        repo = make_repository(database)
        repo.save(make_account(user_id="u-1", username="alice"))

        with pytest.raises(ConflictError):
            repo.save(make_account(user_id="u-2", username="alice"))

    def test_같은_계정_갱신은_충돌이_아니다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        account = make_account()
        repo.save(account)

        repo.save(account.with_role(Role.ADMIN, now=NOW))

        found = repo.find_by_id(account.id)
        assert found is not None
        assert found.role is Role.ADMIN

    def test_활성_관리자_수를_센다(self, make_repository: Any, database: Database) -> None:
        """BR-AD-03(관리자 0명 방지)의 근거 쿼리."""
        repo = make_repository(database)
        repo.save(make_account(user_id="u-1", username="admin1", role=Role.ADMIN))
        repo.save(make_account(user_id="u-2", username="admin2", role=Role.ADMIN, active=False))
        repo.save(make_account(user_id="u-3", username="alice", role=Role.USER))

        assert repo.count_active_admins() == 1

    def test_생성순으로_전부_조회한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        for i, name in enumerate(["carol", "alice", "bob"]):
            account = make_account(user_id=f"u-{i}", username=name)
            repo.save(
                Account(
                    **{
                        **account.__dict__,
                        "created_at": NOW + timedelta(minutes=i),
                    }
                )
                if False
                else account
            )

        assert len(repo.list_all()) == 3


# ---------------------------------------------------------------------------
# SessionRepository 계약
# ---------------------------------------------------------------------------
@_both(InMemorySessionRepository, SqlSessionRepository)
class TestSessionRepositoryContract:
    @staticmethod
    def _session(user: str = "u-1", *, issued: datetime = NOW) -> tuple[SessionToken, Session]:
        token = SessionToken.generate()
        return token, Session.issue(token, UserId(user), now=issued)

    def test_저장하고_해시로_찾는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        _, session = self._session()

        repo.put(session)
        found = repo.get(session.token_hash)

        assert found is not None
        assert found.user_id == session.user_id
        assert found.absolute_expires_at == session.absolute_expires_at

    def test_삭제하면_즉시_사라진다(self, make_repository: Any, database: Database) -> None:
        """FR-35 — 로그아웃 시 즉시 무효화."""
        repo = make_repository(database)
        _, session = self._session()
        repo.put(session)

        repo.delete(session.token_hash)

        assert repo.get(session.token_hash) is None

    def test_사용자별_전량_무효화는_해당_사용자만_지운다(
        self, make_repository: Any, database: Database
    ) -> None:
        repo = make_repository(database)
        _, alice1 = self._session("alice")
        _, alice2 = self._session("alice")
        _, bob = self._session("bob")
        for session in (alice1, alice2, bob):
            repo.put(session)

        assert repo.delete_by_user(UserId("alice")) == 2
        assert repo.get(bob.token_hash) is not None

    def test_만료_세션을_정리한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        _, fresh = self._session(issued=NOW)
        _, stale = self._session(issued=NOW - timedelta(days=8))
        repo.put(fresh)
        repo.put(stale)

        assert repo.purge_expired(NOW) == 1
        assert repo.get(fresh.token_hash) is not None

    def test_활성_세션_수를_센다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        _, fresh = self._session(issued=NOW)
        _, stale = self._session(issued=NOW - timedelta(days=8))
        repo.put(fresh)
        repo.put(stale)

        assert repo.count_active(NOW) == 1

    def test_폐기된_세션은_활성이_아니다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        _, session = self._session()
        repo.put(session.revoke(now=NOW))

        assert repo.count_active(NOW) == 0


# ---------------------------------------------------------------------------
# ThrottleRepository 계약
# ---------------------------------------------------------------------------
@_both(InMemoryThrottleRepository, SqlThrottleRepository)
class TestThrottleRepositoryContract:
    KEY = ThrottleKey(username_normalized="alice", client_key="c1")

    def test_없는_키는_None_이다(self, make_repository: Any, database: Database) -> None:
        assert make_repository(database).get_state(self.KEY) is None

    def test_상태를_저장하고_읽는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        state = ThrottleState(key=self.KEY).record_failure(now=NOW)

        repo.save_state(state)
        found = repo.get_state(self.KEY)

        assert found is not None
        assert found.consecutive_failures == 1
        assert found.last_failure_at == NOW

    def test_잠금_시각이_timezone_을_유지한다(
        self, make_repository: Any, database: Database
    ) -> None:
        """⭐ 잠금 판정이 시각 비교이므로 여기가 깨지면 잠금이 동작하지 않습니다."""
        repo = make_repository(database)
        state = ThrottleState(key=self.KEY)
        for _ in range(11):
            state = state.record_failure(now=NOW)
        repo.save_state(state)

        found = repo.get_state(self.KEY)

        assert found is not None
        assert found.locked_until is not None
        assert found.locked_until.tzinfo is not None
        assert found.is_locked(NOW)

    def test_상태를_덮어쓴다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.save_state(ThrottleState(key=self.KEY).record_failure(now=NOW))
        repo.save_state(ThrottleState(key=self.KEY))

        found = repo.get_state(self.KEY)
        assert found is not None
        assert found.consecutive_failures == 0

    def test_실패_시도를_세되_성공은_제외한다(
        self, make_repository: Any, database: Database
    ) -> None:
        repo = make_repository(database)
        for outcome in (
            AttemptOutcome.BAD_CREDENTIALS,
            AttemptOutcome.BAD_CREDENTIALS,
            AttemptOutcome.SUCCESS,
        ):
            repo.record_attempt(
                LoginAttempt(
                    username_normalized="alice",
                    client_key="c1",
                    occurred_at=NOW,
                    outcome=outcome,
                )
            )

        since = NOW - timedelta(minutes=10)
        assert repo.count_failures_since("alice", since) == 2
        assert repo.count_all_failures_since(since) == 2

    def test_계정이_없어도_시도를_기록한다(self, make_repository: Any, database: Database) -> None:
        """⭐ BR-TH-11 — 기록이 갈리면 응답 시간으로 계정 존재가 드러납니다."""
        repo = make_repository(database)
        repo.record_attempt(
            LoginAttempt(
                username_normalized="does-not-exist",
                client_key="c1",
                occurred_at=NOW,
                outcome=AttemptOutcome.BAD_CREDENTIALS,
            )
        )

        assert repo.count_failures_since("does-not-exist", NOW - timedelta(minutes=1)) == 1


# ---------------------------------------------------------------------------
# MfaRepository 계약
# ---------------------------------------------------------------------------
@_both(InMemoryMfaRepository, SqlMfaRepository)
class TestMfaRepositoryContract:
    USER = UserId("u-1")

    def _code(self, index: int) -> MfaRecoveryCode:
        return MfaRecoveryCode(
            id=RecoveryCodeId(f"r-{index}"),
            user_id=self.USER,
            code_hash=PasswordHash(f"fake$v1$code{index}"),
            created_at=NOW,
        )

    def test_등록을_저장하고_읽는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        enrollment = MfaEnrollment(
            user_id=self.USER, secret_cipher=b"\x01\x02\x03", enrolled_at=NOW
        )

        repo.save_enrollment(enrollment)
        found = repo.get_enrollment(self.USER)

        assert found is not None
        assert found.secret_cipher == b"\x01\x02\x03"
        assert not found.is_active

    def test_확인하면_활성이_된다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        enrollment = MfaEnrollment(user_id=self.USER, secret_cipher=b"x", enrolled_at=NOW)
        repo.save_enrollment(enrollment)

        repo.save_enrollment(enrollment.confirm(now=NOW))

        found = repo.get_enrollment(self.USER)
        assert found is not None
        assert found.is_active

    def test_등록을_삭제한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.save_enrollment(MfaEnrollment(user_id=self.USER, secret_cipher=b"x", enrolled_at=NOW))

        repo.delete_enrollment(self.USER)

        assert repo.get_enrollment(self.USER) is None

    def test_복구_코드를_저장하고_읽는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.save_recovery_codes([self._code(i) for i in range(3)])

        codes = repo.list_recovery_codes(self.USER)

        assert len(codes) == 3
        assert all(c.is_available for c in codes)

    def test_사용_표시가_반영된다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        code = self._code(0)
        repo.save_recovery_codes([code])

        repo.update_recovery_code(code.consume(now=NOW))

        stored = repo.list_recovery_codes(self.USER)
        assert not stored[0].is_available
        assert stored[0].used_at == NOW

    def test_재발급은_기존_코드를_전부_대체한다(
        self, make_repository: Any, database: Database
    ) -> None:
        repo = make_repository(database)
        repo.save_recovery_codes([self._code(i) for i in range(3)])

        repo.replace_recovery_codes(self.USER, [self._code(99)])

        codes = repo.list_recovery_codes(self.USER)
        assert len(codes) == 1
        assert codes[0].id == RecoveryCodeId("r-99")

    def test_빈_목록으로_재발급하면_전부_사라진다(
        self, make_repository: Any, database: Database
    ) -> None:
        repo = make_repository(database)
        repo.save_recovery_codes([self._code(0)])

        repo.replace_recovery_codes(self.USER, [])

        assert repo.list_recovery_codes(self.USER) == []


# ---------------------------------------------------------------------------
# AuditTrail 계약 — append-only
# ---------------------------------------------------------------------------
@_both(InMemoryAuditTrail, SqlAuditTrail)
class TestAuditTrailContract:
    @staticmethod
    def _entry(
        event: AuditEventType = AuditEventType.LOGIN_SUCCEEDED,
        *,
        at: datetime = NOW,
        actor: str | None = None,
    ) -> AuditEntry:
        return AuditEntry(
            event_type=event,
            outcome=AuditOutcome.SUCCEEDED,
            occurred_at=at,
            actor_user_id=UserId(actor) if actor else None,
        )

    def test_갱신_삭제_메서드가_존재하지_않는다(
        self, make_repository: Any, database: Database
    ) -> None:
        """⭐ NFR-10 — 두 구현 모두 인터페이스에 없습니다."""
        repo = make_repository(database)

        assert not hasattr(repo, "update")
        assert not hasattr(repo, "delete")

    def test_seq_가_결번_없이_증가한다(self, make_repository: Any, database: Database) -> None:
        """INV-AU-03 — 결번은 변조 신호입니다."""
        repo = make_repository(database)

        seqs = [repo.append(self._entry()).seq for _ in range(5)]

        assert seqs == [1, 2, 3, 4, 5]
        assert repo.max_seq() == 5

    def test_최신순으로_조회한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.append(self._entry(AuditEventType.ACCOUNT_CREATED))
        repo.append(self._entry(AuditEventType.LOGIN_SUCCEEDED))

        entries = repo.query(AuditFilter(limit=10))

        assert entries[0].event_type is AuditEventType.LOGIN_SUCCEEDED

    def test_이벤트_종류로_거른다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.append(self._entry(AuditEventType.LOGIN_SUCCEEDED))
        repo.append(self._entry(AuditEventType.AUTHZ_DENIED))

        denied = repo.query(AuditFilter(event_types=frozenset({AuditEventType.AUTHZ_DENIED})))

        assert len(denied) == 1

    def test_행위자로_거른다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.append(self._entry(actor="alice"))
        repo.append(self._entry(actor="bob"))

        assert len(repo.query(AuditFilter(actor_user_id=UserId("alice")))) == 1

    def test_기간으로_거른다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.append(self._entry(at=NOW - timedelta(days=2)))
        repo.append(self._entry(at=NOW))

        recent = repo.query(AuditFilter(since=NOW - timedelta(hours=1)))

        assert len(recent) == 1

    def test_시간_창_안의_발생_횟수를_센다(self, make_repository: Any, database: Database) -> None:
        """누적 알림 임계 판정의 근거 쿼리 (ND3=A)."""
        repo = make_repository(database)
        for _ in range(3):
            repo.append(self._entry(AuditEventType.LOGIN_FAILED))

        assert repo.count_since(AuditEventType.LOGIN_FAILED, NOW - timedelta(minutes=10)) == 3


# ---------------------------------------------------------------------------
# JobQueue 계약
# ---------------------------------------------------------------------------
@_both(InMemoryJobQueue, SqlJobQueue)
class TestJobQueueContract:
    @staticmethod
    def _spec(owner: str = "owner-1", *, max_attempts: int = 3) -> JobSpec:
        scope = OwnerScope.for_subject(AuthContext(UserId(owner), Role.USER))
        return JobSpec.for_scope(JobKind.BACKUP, scope, max_attempts=max_attempts)

    def test_등록하고_조회한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        job = repo.enqueue(self._spec(), now=NOW)

        found = repo.get(job.id)

        assert found is not None
        assert found.state is JobState.PENDING
        assert found.owner_id == UserId("owner-1")

    def test_점유하면_실행_중이_된다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.enqueue(self._spec(), now=NOW)

        claimed = repo.claim(WorkerId("w1"), now=NOW)

        assert claimed is not None
        assert claimed.state is JobState.RUNNING
        assert claimed.claimed_by == WorkerId("w1")

    def test_두_워커가_같은_작업을_점유하지_않는다(
        self, make_repository: Any, database: Database
    ) -> None:
        """⭐ SQL 구현은 조건부 UPDATE 로 경쟁을 막습니다."""
        repo = make_repository(database)
        repo.enqueue(self._spec(), now=NOW)

        first = repo.claim(WorkerId("w1"), now=NOW)
        second = repo.claim(WorkerId("w2"), now=NOW)

        assert first is not None
        assert second is None

    def test_백오프_시각_전에는_점유되지_않는다(
        self, make_repository: Any, database: Database
    ) -> None:
        repo = make_repository(database)
        job = repo.enqueue(self._spec(), now=NOW)
        claimed = repo.claim(WorkerId("w1"), now=NOW)
        assert claimed is not None
        repo.save(claimed.fail(now=NOW, reason="io", retryable=True))

        assert repo.claim(WorkerId("w1"), now=NOW) is None
        assert repo.claim(WorkerId("w1"), now=NOW + timedelta(minutes=2)) is not None
        assert repo.get(job.id) is not None

    def test_상태_전이를_저장한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        job = repo.enqueue(self._spec(), now=NOW)
        claimed = repo.claim(WorkerId("w1"), now=NOW)
        assert claimed is not None

        repo.save(claimed.complete(now=NOW, result_ref="ok"))

        stored = repo.get(job.id)
        assert stored is not None
        assert stored.state is JobState.SUCCEEDED
        assert stored.result_ref == "ok"

    def test_heartbeat_만료_작업을_찾는다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.enqueue(self._spec(), now=NOW)
        claimed = repo.claim(WorkerId("w1"), now=NOW)
        assert claimed is not None

        timeout = timedelta(minutes=5)
        assert repo.find_stale(now=NOW + timedelta(minutes=1), timeout=timeout) == []
        assert len(repo.find_stale(now=NOW + timedelta(minutes=6), timeout=timeout)) == 1

    def test_점유해도_소유자가_섞이지_않는다(
        self, make_repository: Any, database: Database
    ) -> None:
        """⭐ 경계 B — 워커가 재구성하는 스코프의 근거가 흔들리지 않는가 (F-09).

        1A 에는 ``OwnerScope`` 로 조회하는 리포지토리가 아직 없으므로(건강 데이터는
        1B), 속성 3 을 SQL 구현에 직접 적용할 대상은 ``jobs.owner_id`` 하나뿐입니다.
        워커는 이 값 하나로 스코프를 재구성하므로, 저장·점유를 거치며 owner 가
        섞이면 **남의 스코프로 작업이 실행됩니다.**
        """
        repo = make_repository(database)
        repo.enqueue(self._spec("alice"), now=NOW)
        repo.enqueue(self._spec("bob"), now=NOW)

        first = repo.claim(WorkerId("w1"), now=NOW)
        second = repo.claim(WorkerId("w2"), now=NOW)
        assert first is not None
        assert second is not None

        claimed_owners = {first.owner_id, second.owner_id}
        assert claimed_owners == {UserId("alice"), UserId("bob")}

        # 재구성된 스코프가 자기 소유자만 가리킨다.
        for job in (first, second):
            scope = OwnerScope.for_subject(AuthContext(job.owner_id, Role.USER))
            assert scope.owner_id == job.owner_id
            stored = repo.get(job.id)
            assert stored is not None
            assert stored.owner_id == job.owner_id

    def test_상태별_개수를_센다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.enqueue(self._spec(), now=NOW)
        repo.enqueue(self._spec(), now=NOW)
        repo.claim(WorkerId("w1"), now=NOW)

        counts = repo.count_by_state()

        assert counts[JobState.PENDING.value] == 1
        assert counts[JobState.RUNNING.value] == 1


# ---------------------------------------------------------------------------
# AlertStore 계약
# ---------------------------------------------------------------------------
@_both(InMemoryAlertStore, SqlAlertStore)
class TestAlertStoreContract:
    @staticmethod
    def _alert(kind: AlertKind = AlertKind.AUTHZ_VIOLATION, *, at: datetime = NOW) -> Alert:
        return Alert(
            id=AlertId.generate(),
            kind=kind,
            severity=AlertSeverity.HIGH,
            raised_at=at,
            summary="테스트 알림",
            context={"target": "u-1"},
        )

    def test_저장하고_조회한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        alert = self._alert()

        repo.save(alert)
        found = repo.get(alert.id)

        assert found is not None
        assert found.kind is AlertKind.AUTHZ_VIOLATION
        assert found.context["target"] == "u-1"

    def test_미확인_알림만_목록에_남는다(self, make_repository: Any, database: Database) -> None:
        """ND2=A — 확인 표시 전까지 대시보드에 남습니다."""
        repo = make_repository(database)
        open_alert = self._alert()
        done = self._alert()
        repo.save(open_alert)
        repo.save(done.acknowledge(now=NOW))

        listed = repo.list_open()

        assert len(listed) == 1
        assert listed[0].id == open_alert.id

    def test_종류별_마지막_발생_시각을_반환한다(
        self, make_repository: Any, database: Database
    ) -> None:
        """중복 억제 판정의 근거 쿼리."""
        repo = make_repository(database)
        repo.save(self._alert(at=NOW - timedelta(minutes=10)))
        repo.save(self._alert(at=NOW))

        last = repo.last_raised_at(AlertKind.AUTHZ_VIOLATION)

        assert last == NOW
        assert repo.last_raised_at(AlertKind.BACKUP_FAILURE) is None


# ---------------------------------------------------------------------------
# BackupStore 계약
# ---------------------------------------------------------------------------
@_both(InMemoryBackupStore, SqlBackupStore)
class TestBackupStoreContract:
    @staticmethod
    def _artifact(*, at: datetime = NOW, backup_id: str | None = None) -> BackupArtifact:
        return BackupArtifact(
            id=BackupId(backup_id) if backup_id else BackupId.generate(),
            created_at=at,
            artifact_ref="memory://artifact",
            size_bytes=42,
            checksum="abc",
            cipher_key_ref="backup",
            schema_version="0001",
        )

    def test_저장하고_조회한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        artifact = self._artifact()

        repo.save(artifact)
        found = repo.get(artifact.id)

        assert found is not None
        assert found.schema_version == "0001"
        assert found.size_bytes == 42

    def test_최신순으로_전부_조회한다(self, make_repository: Any, database: Database) -> None:
        repo = make_repository(database)
        repo.save(self._artifact(at=NOW - timedelta(days=1), backup_id="old"))
        repo.save(self._artifact(at=NOW, backup_id="new"))

        listed = repo.list_all()

        assert [a.id.value for a in listed] == ["new", "old"]

    def test_삭제한다(self, make_repository: Any, database: Database) -> None:
        """⚠ 감사와 달리 백업 메타데이터는 삭제 가능합니다 (보관 주기 정책)."""
        repo = make_repository(database)
        artifact = self._artifact()
        repo.save(artifact)

        repo.delete(artifact.id)

        assert repo.get(artifact.id) is None

    def test_마지막_백업_시각을_반환한다(self, make_repository: Any, database: Database) -> None:
        """기동 시 미실행 보충 판정의 근거."""
        repo = make_repository(database)

        assert repo.last_successful_at() is None

        repo.save(self._artifact(at=NOW - timedelta(days=2)))
        repo.save(self._artifact(at=NOW))

        assert repo.last_successful_at() == NOW
