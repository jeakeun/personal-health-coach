"""identity 도메인 불변식 테스트 (S26)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phc.identity.domain.account import Account
from phc.identity.domain.mfa import MfaEnrollment, MfaRecoveryCode, RecoveryCodeId
from phc.identity.domain.session import (
    Session,
    SessionInvalidReason,
    hash_token,
)
from phc.identity.domain.throttle import (
    DEFAULT_LOCKOUT_THRESHOLD,
    ThrottleKey,
    ThrottleState,
)
from phc.shared import PasswordHash, Role, SessionToken, UserId, Username

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def make_account(*, role: Role = Role.USER, active: bool = True) -> Account:
    return Account(
        id=UserId("u-1"),
        username=Username.parse("alice"),
        display_name="Alice",
        password_hash=PasswordHash("fake$v1$abc"),
        role=role,
        is_active=active,
        must_change_password=False,
        created_at=NOW,
        updated_at=NOW,
    )


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
class TestAccount:
    def test_요약에는_건강_데이터도_해시도_없다(self) -> None:
        """⭐ 관리자 화면이 표현할 수 있는 것의 상한 (US-48, BR-AD-02/09)."""
        summary = make_account().summary()
        fields = set(summary.__slots__)

        assert "password_hash" not in fields
        assert fields == {
            "id",
            "username",
            "display_name",
            "role",
            "is_active",
            "last_login_at",
        }

    def test_이메일_필드가_존재하지_않는다(self) -> None:
        """INV-AC-04 — 쓰이지 않는 개인정보를 수집하지 않습니다 (F1=A)."""
        assert not any("email" in name for name in Account.__slots__)

    def test_활성_관리자만_is_active_admin_이다(self) -> None:
        assert make_account(role=Role.ADMIN).is_active_admin
        assert not make_account(role=Role.ADMIN, active=False).is_active_admin
        assert not make_account(role=Role.USER).is_active_admin

    def test_비활성_계정은_로그인할_수_없다(self) -> None:
        assert not make_account(active=False).can_sign_in

    def test_전이는_새_인스턴스를_반환한다(self) -> None:
        account = make_account()
        changed = account.with_role(Role.ADMIN, now=NOW)

        assert account.role is Role.USER  # 원본 불변
        assert changed.role is Role.ADMIN


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class TestSession:
    def _session(self) -> tuple[SessionToken, Session]:
        token = SessionToken.generate()
        return token, Session.issue(token, UserId("u-1"), now=NOW)

    def test_저장소에는_해시만_남는다(self) -> None:
        """INV-SE-03 — 원문을 복원할 수 없습니다."""
        token, session = self._session()
        assert session.token_hash != token.value
        assert session.token_hash == hash_token(token)

    def test_발급_직후에는_유효하다(self) -> None:
        _, session = self._session()
        assert session.is_valid(NOW)

    def test_유휴_만료_경계(self) -> None:
        _, session = self._session()
        assert session.is_valid(NOW + timedelta(minutes=59, seconds=59))
        assert not session.is_valid(NOW + timedelta(minutes=60, seconds=1))

    def test_절대_만료_경계(self) -> None:
        _, session = self._session()
        just_before = NOW + timedelta(days=7) - timedelta(seconds=1)
        # 유휴 만료를 계속 갱신해도 절대 만료는 밀리지 않습니다.
        touched = session
        for _ in range(200):
            touched = touched.touch(now=just_before)

        assert touched.is_valid(just_before)
        assert not touched.is_valid(NOW + timedelta(days=7, seconds=1))

    def test_활동이_있어도_절대_만료는_갱신되지_않는다(self) -> None:
        """⭐ INV-SE-02 — 갱신하면 세션이 영원히 살아 있게 됩니다."""
        _, session = self._session()
        touched = session.touch(now=NOW + timedelta(minutes=30))

        assert touched.idle_expires_at > session.idle_expires_at
        assert touched.absolute_expires_at == session.absolute_expires_at

    def test_폐기_사유를_구분한다(self) -> None:
        _, session = self._session()

        assert session.revoke(now=NOW).invalid_reason(NOW) is SessionInvalidReason.REVOKED
        assert (
            session.invalid_reason(NOW + timedelta(minutes=61)) is SessionInvalidReason.IDLE_EXPIRED
        )
        assert (
            session.invalid_reason(NOW + timedelta(days=8)) is SessionInvalidReason.ABSOLUTE_EXPIRED
        )


# ---------------------------------------------------------------------------
# ThrottleState — 지연 곡선과 잠금
# ---------------------------------------------------------------------------
class TestThrottleState:
    KEY = ThrottleKey(username_normalized="alice", client_key="c1")

    def test_지연이_지수적으로_늘고_8초에서_멈춘다(self) -> None:
        state = ThrottleState(key=self.KEY)
        observed = []
        for _ in range(7):
            observed.append(state.delay_seconds())
            state = state.record_failure(now=NOW)

        assert observed == [0, 1, 2, 4, 8, 8, 8]

    def test_임계_초과에서만_잠긴다(self) -> None:
        state = ThrottleState(key=self.KEY)
        for _ in range(DEFAULT_LOCKOUT_THRESHOLD):
            state = state.record_failure(now=NOW)

        assert not state.is_locked(NOW), "임계와 같은 횟수에서는 아직 잠기지 않습니다"

        state = state.record_failure(now=NOW)
        assert state.is_locked(NOW)

    def test_잠금은_시간_경과로_자동_해제된다(self) -> None:
        """INV-TH-01 — 별도 해제 작업이 필요 없습니다 (F2=A)."""
        state = ThrottleState(key=self.KEY)
        for _ in range(DEFAULT_LOCKOUT_THRESHOLD + 1):
            state = state.record_failure(now=NOW)

        assert state.is_locked(NOW + timedelta(minutes=14))
        assert not state.is_locked(NOW + timedelta(minutes=16))

    def test_성공하면_초기화된다(self) -> None:
        """INV-TH-02."""
        state = ThrottleState(key=self.KEY)
        for _ in range(5):
            state = state.record_failure(now=NOW)

        reset = state.record_success()
        assert reset.consecutive_failures == 0
        assert reset.locked_until is None

    def test_계정을_참조하지_않는다(self) -> None:
        """⭐ 존재하지 않는 사용자명도 상태를 가져야 열거를 막습니다 (BR-TH-11)."""
        assert not any("account" in name for name in ThrottleState.__slots__)


# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------
class TestMfaDomain:
    def test_확인_전_등록은_활성이_아니다(self) -> None:
        """INV-MF-02 — 인증 앱 등록 실패로 스스로 갇히는 것을 막습니다."""
        enrollment = MfaEnrollment(user_id=UserId("u-1"), secret_cipher=b"cipher", enrolled_at=NOW)
        assert not enrollment.is_active
        assert enrollment.confirm(now=NOW).is_active

    def test_평문_비밀키_필드가_없다(self) -> None:
        """INV-MF-01."""
        assert "secret_cipher" in MfaEnrollment.__slots__
        assert "secret" not in MfaEnrollment.__slots__

    def test_복구_코드는_1회용이다(self) -> None:
        """INV-RC-02."""
        code = MfaRecoveryCode(
            id=RecoveryCodeId("r-1"),
            user_id=UserId("u-1"),
            code_hash=PasswordHash("fake$v1$x"),
            created_at=NOW,
        )
        used = code.consume(now=NOW)

        assert not used.is_available
        with pytest.raises(ValueError, match="이미 사용된"):
            used.consume(now=NOW)
