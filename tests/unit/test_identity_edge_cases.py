"""identity 경계·실패 경로 테스트 (S26).

주 경로는 ``test_identity_services.py`` 가 다룹니다. 여기는 **실패 경로와
운영 보조 기능** — 즉 평소에는 안 도는데 사고 때 도는 코드입니다.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from phc.identity.domain.throttle import ThrottleKey
from phc.identity.services.sessions import SessionManager
from phc.identity.services.throttling import LoginThrottle
from phc.shared import (
    AuthContext,
    DomainError,
    PolicyViolationError,
    Role,
    SecretStr,
    SessionToken,
    UndeterminedError,
    UserId,
)
from phc.shared.ports.clock import FixedClock
from tests.conftest import NOW, IdentityFixture, build_identity

GOOD_PASSWORD = SecretStr("correct-horse-battery")
CLIENT = "client-1"


class _BrokenSessionRepository:
    """조회가 실패하는 저장소 — ⛔ fail closed 경로 검증용."""

    def put(self, session: object) -> None: ...

    def get(self, token_hash: str) -> object:
        raise OSError("저장소 접근 실패")

    def delete(self, token_hash: str) -> None: ...

    def delete_by_user(self, user_id: UserId) -> int:
        return 0

    def purge_expired(self, now: object) -> int:
        return 0

    def count_active(self, now: object) -> int:
        return 0


class _BrokenThrottleRepository:
    def get_state(self, key: ThrottleKey) -> object:
        raise OSError("스로틀 저장소 접근 실패")

    def save_state(self, state: object) -> None: ...

    def record_attempt(self, attempt: object) -> None: ...

    def count_failures_since(self, username_normalized: str, since: object) -> int:
        return 0

    def count_all_failures_since(self, since: object) -> int:
        return 0


# ---------------------------------------------------------------------------
# ⛔ fail closed — 저장소 장애 시 거부
# ---------------------------------------------------------------------------
class TestFailClosed:
    def test_세션_저장소_장애는_판정_불가로_거부된다(self) -> None:
        """BR-SE-10 — '조회를 못 했으니 통과' 가 아닙니다."""
        manager = SessionManager(
            repository=_BrokenSessionRepository(),  # type: ignore[arg-type]
            clock=FixedClock(NOW),
        )
        with pytest.raises(UndeterminedError):
            manager.resolve(SessionToken("any-token"))

    def test_스로틀_저장소_장애는_판정_불가로_거부된다(self) -> None:
        """BR-TH-06 — 스로틀 상태를 모르는 채 통과시키면 방어가 없습니다."""
        throttle = LoginThrottle(
            repository=_BrokenThrottleRepository(),  # type: ignore[arg-type]
            clock=FixedClock(NOW),
            sleep=lambda _: None,
        )
        with pytest.raises(UndeterminedError):
            throttle.check(ThrottleKey(username_normalized="alice", client_key=CLIENT))


# ---------------------------------------------------------------------------
# 세션 운영 보조
# ---------------------------------------------------------------------------
class TestSessionMaintenance:
    def _issued(self, fx: IdentityFixture) -> object:
        result = fx.auth.sign_up("alice", GOOD_PASSWORD)
        account = fx.accounts.find_by_id(result.user_id)
        assert account is not None
        return fx.sessions.issue(account)

    def test_만료_세션을_정리한다(self, identity: IdentityFixture) -> None:
        self._issued(identity)
        assert identity.sessions.active_count() == 1

        identity.clock.advance(timedelta(days=8))

        assert identity.sessions.purge_expired() == 1
        assert identity.sessions.active_count() == 0

    def test_인증_컨텍스트를_계정에서_만든다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)
        assert account is not None
        issued = identity.sessions.issue(account)

        ctx = identity.sessions.to_context(issued.session, account)

        assert ctx.subject_id == account.id
        assert ctx.role is Role.USER
        assert not ctx.must_change_password

    def test_만료_시각은_둘_중_이른_쪽이다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)
        assert account is not None
        issued = identity.sessions.issue(account)

        expires = identity.sessions.expires_at(issued.session)

        assert expires == issued.session.idle_expires_at
        assert identity.sessions.idle_lifetime == timedelta(minutes=60)

    def test_전량_무효화는_해당_사용자만_끊는다(self, identity: IdentityFixture) -> None:
        alice = identity.auth.sign_up("alice", GOOD_PASSWORD)
        bob = identity.auth.sign_up("bob", GOOD_PASSWORD)
        alice_account = identity.accounts.find_by_id(alice.user_id)
        bob_account = identity.accounts.find_by_id(bob.user_id)
        assert alice_account is not None and bob_account is not None

        identity.sessions.issue(alice_account)
        bob_session = identity.sessions.issue(bob_account)

        assert identity.sessions.revoke_all_for(alice.user_id) == 1
        assert identity.sessions.resolve(bob_session.token) is not None


# ---------------------------------------------------------------------------
# 관리자 서비스 실패 경로
# ---------------------------------------------------------------------------
class TestAdminFailurePaths:
    def _with_admin(self) -> tuple[IdentityFixture, AuthContext]:
        fx = build_identity()
        fx.bootstrapper.bootstrap()
        admin = fx.account("admin")
        return fx, AuthContext(admin.id, Role.ADMIN)

    def test_없는_계정에_대한_조작은_거부된다(self) -> None:
        fx, ctx = self._with_admin()

        with pytest.raises(DomainError, match="계정을 찾을 수 없습니다"):
            fx.admin.set_role(ctx, UserId("ghost"), Role.ADMIN)
        with pytest.raises(DomainError):
            fx.admin.set_active(ctx, UserId("ghost"), False)
        with pytest.raises(DomainError):
            fx.admin.reset_password(ctx, UserId("ghost"))

    def test_같은_역할로_바꾸면_아무_일도_일어나지_않는다(self) -> None:
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)
        before = fx.audit.max_seq()

        fx.admin.set_role(ctx, target.user_id, Role.USER)

        assert fx.audit.max_seq() == before

    def test_같은_활성_상태로_바꾸면_아무_일도_일어나지_않는다(self) -> None:
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)
        before = fx.audit.max_seq()

        fx.admin.set_active(ctx, target.user_id, True)

        assert fx.audit.max_seq() == before

    def test_비활성화_후_다시_활성화할_수_있다(self) -> None:
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)

        fx.admin.set_active(ctx, target.user_id, False)
        fx.admin.set_active(ctx, target.user_id, True)

        account = fx.accounts.find_by_id(target.user_id)
        assert account is not None
        assert account.is_active

    def test_관리자가_둘이면_한_명은_비활성화할_수_있다(self) -> None:
        fx, ctx = self._with_admin()
        second = fx.auth.sign_up("bob", GOOD_PASSWORD)
        fx.admin.set_role(ctx, second.user_id, Role.ADMIN)

        fx.admin.set_active(ctx, second.user_id, False)

        assert fx.accounts.count_active_admins() == 1


# ---------------------------------------------------------------------------
# 인증 실패 경로
# ---------------------------------------------------------------------------
class TestAuthFailurePaths:
    def test_형식이_잘못된_사용자명은_거부된다(self, identity: IdentityFixture) -> None:
        with pytest.raises(PolicyViolationError, match=r"invalid_username|사용자명"):
            identity.auth.sign_up("a", GOOD_PASSWORD)

    def test_없는_계정의_비밀번호는_변경할_수_없다(self, identity: IdentityFixture) -> None:
        ctx = AuthContext(UserId("ghost"), Role.USER)

        with pytest.raises(DomainError, match="계정을 찾을 수 없습니다"):
            identity.auth.change_password(ctx, GOOD_PASSWORD, SecretStr("new-password-1"))

    def test_새_비밀번호도_정책을_통과해야_한다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        ctx = AuthContext(result.user_id, Role.USER)

        with pytest.raises(PolicyViolationError, match="8자 이상"):
            identity.auth.change_password(ctx, GOOD_PASSWORD, SecretStr("short"))

    def test_MFA_코드가_틀리면_세션이_발급되지_않는다(self) -> None:
        fx = build_identity()
        result = fx.auth.sign_up("alice", GOOD_PASSWORD)
        fx.mfa.begin_enrollment(result.user_id, "alice")
        fx.mfa.confirm_enrollment(result.user_id, "123456")

        outcome = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT, mfa_code="999999")

        assert not outcome.succeeded
        assert outcome.session is None


# ---------------------------------------------------------------------------
# MFA 실패 경로
# ---------------------------------------------------------------------------
class TestMfaFailurePaths:
    def test_등록_전에는_확인할_수_없다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)

        with pytest.raises(DomainError, match="등록을 먼저"):
            identity.mfa.confirm_enrollment(result.user_id, "123456")

    def test_잘못된_코드로는_확인되지_않는다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        identity.mfa.begin_enrollment(result.user_id, "alice")

        with pytest.raises(DomainError, match="올바르지 않습니다"):
            identity.mfa.confirm_enrollment(result.user_id, "000000")

    def test_등록하지_않은_사용자의_검증은_실패한다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)

        assert not identity.mfa.verify(result.user_id, "123456").ok

    def test_MFA_를_해제하면_요구되지_않는다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        identity.mfa.begin_enrollment(result.user_id, "alice")
        identity.mfa.confirm_enrollment(result.user_id, "123456")
        assert identity.mfa.is_required(result.user_id)

        identity.mfa.disable(result.user_id)

        assert not identity.mfa.is_required(result.user_id)
        assert identity.mfa_repo.list_recovery_codes(result.user_id) == []

    def test_복구_코드를_재발급하면_이전_코드는_무효다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        identity.mfa.begin_enrollment(result.user_id, "alice")
        old = identity.mfa.confirm_enrollment(result.user_id, "123456")

        identity.mfa.reissue_recovery_codes(result.user_id)

        assert not identity.mfa.verify(result.user_id, old.codes[0].reveal()).ok

    def test_잔량이_적으면_경고_플래그가_선다(self, identity: IdentityFixture) -> None:
        """BR-MF-06 — 복구 코드가 떨어지기 전에 알립니다."""
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        identity.mfa.begin_enrollment(result.user_id, "alice")
        bundle = identity.mfa.confirm_enrollment(result.user_id, "123456")

        results = [identity.mfa.verify(result.user_id, c.reveal()) for c in bundle.codes[:8]]

        assert all(r.ok and r.used_recovery_code for r in results)
        assert results[-1].should_warn_low_codes
