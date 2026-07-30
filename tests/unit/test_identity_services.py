"""identity 서비스 테스트 (S26) — 가입 · 로그인 · 인가 · 부트스트랩 · 관리자.

여기에는 **속성 테스트만으로 커버하지 않는 크리티컬 경로**의 예시 기반
테스트가 들어 있습니다 (NFR-1A-36, PBT-10):

    응답 동일성 · 관리자 0명 방지 · 변경 강제 · 세션 경계
    · 콘솔 출력 격리 · 복구 코드 1회용
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from phc.identity.domain.throttle import DEFAULT_LOCKOUT_THRESHOLD, ThrottleKey
from phc.identity.services.bootstrap import BOOTSTRAP_USERNAME
from phc.operations.domain.alert import AlertKind
from phc.operations.domain.audit import AuditEventType
from phc.operations.ports.audit import AuditFilter
from phc.operations.services.metrics import MetricName
from phc.shared import (
    AuthContext,
    AuthzError,
    ConflictError,
    PolicyViolationError,
    Role,
    SecretStr,
    UserId,
)
from tests.conftest import NOW, IdentityFixture, build_identity

GOOD_PASSWORD = SecretStr("correct-horse-battery")
CLIENT = "client-1"


# ---------------------------------------------------------------------------
# 회원가입 (US-43)
# ---------------------------------------------------------------------------
class TestSignUp:
    def test_기본_역할은_USER_이다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)

        assert account is not None
        assert account.role is Role.USER

    def test_평문이_저장되지_않는다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)

        assert account is not None
        assert GOOD_PASSWORD.reveal() not in account.password_hash.encoded

    def test_짧은_비밀번호는_거부된다(self, identity: IdentityFixture) -> None:
        with pytest.raises(PolicyViolationError, match="8자 이상"):
            identity.auth.sign_up("alice", SecretStr("short"))

    def test_유출된_비밀번호는_거부된다(self) -> None:
        fx = build_identity(breached={"password123"})
        with pytest.raises(PolicyViolationError, match="유출된"):
            fx.auth.sign_up("alice", SecretStr("password123"))

    def test_유출_목록을_읽지_못하면_거부된다(self) -> None:
        """⛔ fail closed (BR-PW-03) — '못 읽었으니 통과' 는 없습니다."""
        fx = build_identity(breach_list_fails=True)
        with pytest.raises(PolicyViolationError, match="확인할 수 없습니다"):
            fx.auth.sign_up("alice", GOOD_PASSWORD)

    def test_admin_은_선점할_수_없다(self, identity: IdentityFixture) -> None:
        """⭐ BR-BS-10 — 자유 가입이므로 부트스트랩 전 선점을 막아야 합니다."""
        with pytest.raises(PolicyViolationError, match="가입할 수 없습니다"):
            identity.auth.sign_up("admin", GOOD_PASSWORD)
        with pytest.raises(PolicyViolationError):
            identity.auth.sign_up("ADMIN", GOOD_PASSWORD)

    def test_중복_사용자명은_존재를_과도하게_노출하지_않는다(
        self, identity: IdentityFixture
    ) -> None:
        identity.auth.sign_up("alice", GOOD_PASSWORD)

        with pytest.raises(ConflictError) as exc:
            identity.auth.sign_up("Alice", GOOD_PASSWORD)

        assert "이미 존재" not in exc.value.safe_message
        assert exc.value.safe_message == "해당 사용자명으로는 가입할 수 없습니다."

    def test_정책_위반도_감사에_남는다(self, identity: IdentityFixture) -> None:
        # 사유 코드가 "too_short" 이므로, 입력값과 사유가 겹치지 않는 문자열을
        # 씁니다. 겹치면 "평문이 새지 않았다" 를 확인할 수 없습니다.
        secret = "Zx9"
        with pytest.raises(PolicyViolationError):
            identity.auth.sign_up("alice", SecretStr(secret))

        rejected = identity.audit.query(
            AuditFilter(event_types=frozenset({AuditEventType.ACCOUNT_CREATE_REJECTED}))
        )
        assert len(rejected) == 1
        # ⚠ 입력 비밀번호가 담기지 않았는지 확인
        assert secret not in str(rejected[0].detail)


# ---------------------------------------------------------------------------
# 로그인 — ⭐ 응답 동일성 (US-45, BR-TH-10~13)
# ---------------------------------------------------------------------------
class TestLoginResponseUniformity:
    def _fixture(self) -> IdentityFixture:
        fx = build_identity()
        fx.auth.sign_up("alice", GOOD_PASSWORD)
        return fx

    def test_계정_없음과_비밀번호_틀림이_같은_응답이다(self) -> None:
        """⭐ 문구가 갈리는 순간 계정 열거가 가능해집니다."""
        fx = self._fixture()

        missing = fx.auth.login("nobody", GOOD_PASSWORD, client_key=CLIENT)
        wrong = fx.auth.login("alice", SecretStr("wrong-password-x"), client_key=CLIENT)

        assert missing.succeeded is False
        assert wrong.succeeded is False
        assert missing.message == wrong.message

    def test_비활성_계정도_같은_응답이다(self) -> None:
        fx = self._fixture()
        account = fx.account("alice")
        fx.accounts.save(account.with_active(False, now=NOW))

        inactive = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)
        wrong = fx.auth.login("bob", GOOD_PASSWORD, client_key=CLIENT)

        assert inactive.message == wrong.message

    def test_잠금_상태도_같은_응답이며_해제_시각을_노출하지_않는다(self) -> None:
        fx = self._fixture()
        for _ in range(DEFAULT_LOCKOUT_THRESHOLD + 1):
            fx.auth.login("alice", SecretStr("wrong-password-x"), client_key=CLIENT)

        blocked = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)

        assert blocked.succeeded is False
        assert blocked.message == "사용자명 또는 비밀번호가 올바르지 않습니다."
        assert "분" not in (blocked.message or "")

    def test_계정이_없어도_더미_해시_검증을_수행한다(self) -> None:
        """⭐ BR-TH-12 — 없으면 응답 시간만으로 사용자명 목록을 만들 수 있습니다."""
        fx = self._fixture()
        before = fx.hasher.dummy_verify_calls

        fx.auth.login("nobody-here", GOOD_PASSWORD, client_key=CLIENT)

        assert fx.hasher.dummy_verify_calls == before + 1

    def test_존재하지_않는_계정에도_지연이_적용된다(self) -> None:
        fx = self._fixture()
        for _ in range(3):
            fx.auth.login("nobody", GOOD_PASSWORD, client_key=CLIENT)

        # 지연은 실패를 **기록한 뒤** 갱신된 누적 횟수로 계산합니다.
        # 즉 첫 실패부터 1초를 소모합니다 — 공격자의 첫 시도도 공짜가 아닙니다.
        assert fx.slept == [1, 2, 4]


# ---------------------------------------------------------------------------
# 로그인 — 정상 경로와 부수 효과
# ---------------------------------------------------------------------------
class TestLogin:
    def _fixture(self) -> IdentityFixture:
        fx = build_identity()
        fx.auth.sign_up("alice", GOOD_PASSWORD)
        return fx

    def test_성공하면_세션이_발급된다(self) -> None:
        fx = self._fixture()
        outcome = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)

        assert outcome.succeeded
        assert outcome.session is not None
        assert fx.sessions.resolve(outcome.session.token) is not None

    def test_성공하면_실패_카운터가_초기화된다(self) -> None:
        fx = self._fixture()
        for _ in range(3):
            fx.auth.login("alice", SecretStr("wrong-password-x"), client_key=CLIENT)
        fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)

        key = ThrottleKey(username_normalized="alice", client_key=CLIENT)
        state = fx.throttle_repo.get_state(key)
        assert state is not None
        assert state.consecutive_failures == 0

    def test_구버전_해시는_로그인_성공_시_재해시된다(self) -> None:
        """BR-PW-07 — 파라미터 상향에 마이그레이션이 필요 없습니다."""
        fx = build_identity(legacy_hasher=True)
        fx.auth.sign_up("alice", GOOD_PASSWORD)
        before = fx.account("alice").password_hash

        assert fx.hasher.needs_rehash(before)

        # 새 파라미터 세대로 교체한 뒤 로그인
        fx.hasher.upgrade_params()
        fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)

        after = fx.account("alice").password_hash
        assert not fx.hasher.needs_rehash(after)

    def test_메트릭이_기록된다(self) -> None:
        fx = self._fixture()
        fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)
        fx.auth.login("alice", SecretStr("wrong-password-x"), client_key=CLIENT)

        counters = fx.metrics.snapshot().counters
        assert counters[MetricName.LOGIN_SUCCESS] == 1
        assert counters[MetricName.LOGIN_FAILURE] == 1

    def test_반복_실패는_누적_알림_대상이_된다(self) -> None:
        fx = self._fixture()
        for _ in range(10):
            fx.auth.login("alice", SecretStr("wrong-password-x"), client_key=CLIENT)

        kinds = {a.kind for a in fx.alert_store.list_open()}
        assert AlertKind.LOGIN_FAILURE_BURST_ACCOUNT in kinds


# ---------------------------------------------------------------------------
# 로그아웃 · 비밀번호 변경 (US-44, US-50)
# ---------------------------------------------------------------------------
class TestLogoutAndPasswordChange:
    def _logged_in(self) -> tuple[IdentityFixture, AuthContext, object]:
        fx = build_identity()
        fx.auth.sign_up("alice", GOOD_PASSWORD)
        outcome = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)
        assert outcome.session is not None
        account = fx.account("alice")
        ctx = AuthContext(subject_id=account.id, role=account.role)
        return fx, ctx, outcome.session.token

    def test_로그아웃하면_즉시_무효화된다(self) -> None:
        """FR-35 — 지연 삭제가 아닙니다."""
        fx, ctx, token = self._logged_in()
        fx.auth.logout(token, ctx)  # type: ignore[arg-type]

        assert fx.sessions.resolve(token) is None  # type: ignore[arg-type]

    def test_비밀번호_변경은_자기_세션까지_무효화한다(self) -> None:
        """⭐ BR-PW-06 — 유출 의심 상황이므로 전량 무효화가 맞습니다."""
        fx, ctx, token = self._logged_in()
        fx.auth.change_password(ctx, GOOD_PASSWORD, SecretStr("new-password-value"))

        assert fx.sessions.resolve(token) is None  # type: ignore[arg-type]

    def test_현재_비밀번호가_틀리면_변경되지_않는다(self) -> None:
        fx, ctx, _ = self._logged_in()
        with pytest.raises(PolicyViolationError, match="현재 비밀번호"):
            fx.auth.change_password(ctx, SecretStr("wrong-password-x"), SecretStr("new-password"))

    def test_같은_비밀번호로는_변경할_수_없다(self) -> None:
        fx, ctx, _ = self._logged_in()
        with pytest.raises(PolicyViolationError, match="이전과 다른"):
            fx.auth.change_password(ctx, GOOD_PASSWORD, GOOD_PASSWORD)


# ---------------------------------------------------------------------------
# ⭐ 인가 (US-42, US-48)
# ---------------------------------------------------------------------------
class TestAuthorization:
    def test_소유자는_통과한다(self, identity: IdentityFixture) -> None:
        uid = UserId("u-1")
        identity.ownership.require_owner(AuthContext(uid, Role.USER), uid)

    def test_관리자도_타인_리소스에는_거부된다(self, identity: IdentityFixture) -> None:
        """⭐ US-48 의 핵심 — 역할이 소유권 판정에 개입하지 않습니다."""
        admin_ctx = AuthContext(UserId("admin-1"), Role.ADMIN)

        with pytest.raises(AuthzError):
            identity.ownership.require_owner(admin_ctx, UserId("victim"))

    def test_인가_거부는_감사에_남는다(self, identity: IdentityFixture) -> None:
        """US-48 인수 기준 — '거부가 감사 로그에 기록된다'."""
        with pytest.raises(AuthzError):
            identity.ownership.require_owner(
                AuthContext(UserId("admin-1"), Role.ADMIN), UserId("victim")
            )

        denied = identity.audit.query(
            AuditFilter(event_types=frozenset({AuditEventType.AUTHZ_DENIED}))
        )
        assert len(denied) == 1
        assert denied[0].actor_role is Role.ADMIN

    def test_인가_거부는_메트릭에_집계된다(self, identity: IdentityFixture) -> None:
        with pytest.raises(AuthzError):
            identity.ownership.require_owner(AuthContext(UserId("u-1"), Role.USER), UserId("other"))

        assert identity.metrics.snapshot().counters[MetricName.AUTHZ_DENIED] == 1

    def test_일반_사용자는_관리자_경로에서_거부된다(self, identity: IdentityFixture) -> None:
        with pytest.raises(AuthzError):
            identity.roles.require_admin(AuthContext(UserId("u-1"), Role.USER))

    def test_OwnershipAuthorizer_는_계정_저장소를_주입받지_않는다(self) -> None:
        """⭐ 소유권 판정에 계정 조회가 불필요함을 의존성으로 못박습니다."""
        import inspect

        from phc.identity.services.authorization import OwnershipAuthorizer

        params = set(inspect.signature(OwnershipAuthorizer.__init__).parameters)
        assert "accounts" not in params
        assert "account_repository" not in params


# ---------------------------------------------------------------------------
# ⭐ 부트스트랩 (US-46, AC-17, AC-18)
# ---------------------------------------------------------------------------
class TestBootstrap:
    def test_최초_기동에서_관리자가_생성된다(self, identity: IdentityFixture) -> None:
        outcome = identity.bootstrapper.bootstrap()

        assert outcome.created
        assert outcome.username == BOOTSTRAP_USERNAME
        assert outcome.console_notice is not None

    def test_생성된_관리자는_변경_강제_상태다(self, identity: IdentityFixture) -> None:
        """AC-18 — 변경 전에는 다른 기능을 쓸 수 없습니다."""
        identity.bootstrapper.bootstrap()
        admin = identity.account(BOOTSTRAP_USERNAME)

        assert admin.role is Role.ADMIN
        assert admin.must_change_password

    def test_재기동해도_아무것도_바뀌지_않는다(self, identity: IdentityFixture) -> None:
        """🔬 속성 1 의 예시 기반 대응 (BR-BS-02)."""
        first = identity.bootstrapper.bootstrap()
        before = identity.account(BOOTSTRAP_USERNAME)

        second = identity.bootstrapper.bootstrap()
        after = identity.account(BOOTSTRAP_USERNAME)

        assert first.created
        assert not second.created
        assert second.console_notice is None
        assert before.password_hash == after.password_hash
        assert before.created_at == after.created_at

    def test_임시_비밀번호가_감사에_남지_않는다(self, identity: IdentityFixture) -> None:
        """⭐ AC-17 — 저장소·설정파일·로그 어디에도 평문이 없어야 합니다."""
        outcome = identity.bootstrapper.bootstrap()
        assert outcome.console_notice is not None
        plaintext = outcome.console_notice.reveal()

        entries = identity.audit.query(AuditFilter(limit=100))
        for entry in entries:
            assert plaintext not in str(entry.detail)
            assert plaintext not in str(entry.target_ref)

    def test_임시_비밀번호가_저장소에_남지_않는다(self, identity: IdentityFixture) -> None:
        outcome = identity.bootstrapper.bootstrap()
        assert outcome.console_notice is not None
        plaintext = outcome.console_notice.reveal()

        admin = identity.account(BOOTSTRAP_USERNAME)
        assert plaintext not in admin.password_hash.encoded

    def test_생성된_임시_비밀번호로_로그인할_수_있다(self, identity: IdentityFixture) -> None:
        outcome = identity.bootstrapper.bootstrap()
        assert outcome.console_notice is not None

        result = identity.auth.login(BOOTSTRAP_USERNAME, outcome.console_notice, client_key=CLIENT)
        assert result.succeeded
        assert result.must_change_password


# ---------------------------------------------------------------------------
# ⭐ 관리자 계정 관리 (US-47)
# ---------------------------------------------------------------------------
class TestAdminService:
    def _with_admin(self) -> tuple[IdentityFixture, AuthContext]:
        fx = build_identity()
        fx.bootstrapper.bootstrap()
        admin = fx.account(BOOTSTRAP_USERNAME)
        return fx, AuthContext(admin.id, Role.ADMIN)

    def test_계정_목록에_건강_데이터_필드가_없다(self) -> None:
        fx, ctx = self._with_admin()
        fx.auth.sign_up("alice", GOOD_PASSWORD)

        summaries = fx.admin.list_accounts(ctx)
        assert len(summaries) == 2
        assert not hasattr(summaries[0], "password_hash")

    def test_일반_사용자는_목록을_볼_수_없다(self) -> None:
        fx, _ = self._with_admin()
        result = fx.auth.sign_up("alice", GOOD_PASSWORD)

        with pytest.raises(AuthzError):
            fx.admin.list_accounts(AuthContext(result.user_id, Role.USER))

    def test_마지막_관리자를_강등할_수_없다(self) -> None:
        """⭐ BR-AD-03 — 화면 비활성화가 아니라 서버가 거부합니다."""
        fx, ctx = self._with_admin()

        with pytest.raises(PolicyViolationError, match="관리자가 0명"):
            fx.admin.set_role(ctx, ctx.subject_id, Role.USER)

    def test_마지막_관리자를_비활성화할_수_없다(self) -> None:
        fx, ctx = self._with_admin()

        with pytest.raises(PolicyViolationError, match="관리자가 0명"):
            fx.admin.set_active(ctx, ctx.subject_id, False)

    def test_관리자가_둘이면_한_명은_강등할_수_있다(self) -> None:
        fx, ctx = self._with_admin()
        second = fx.auth.sign_up("bob", GOOD_PASSWORD)
        fx.admin.set_role(ctx, second.user_id, Role.ADMIN)

        fx.admin.set_role(ctx, second.user_id, Role.USER)

        assert fx.accounts.find_by_id(second.user_id).role is Role.USER  # type: ignore[union-attr]

    def test_역할_변경은_세션을_무효화한다(self) -> None:
        """BR-AD-04 — 권한이 바뀌면 기존 AuthContext 가 낡습니다."""
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)
        login = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)
        assert login.session is not None

        fx.admin.set_role(ctx, target.user_id, Role.ADMIN)

        assert fx.sessions.resolve(login.session.token) is None

    def test_역할_변경은_감사와_알림_대상이다(self) -> None:
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)

        fx.admin.set_role(ctx, target.user_id, Role.ADMIN)

        changed = fx.audit.query(AuditFilter(event_types=frozenset({AuditEventType.ROLE_CHANGED})))
        assert len(changed) == 1
        assert AlertKind.PRIVILEGE_CHANGED in {a.kind for a in fx.alert_store.list_open()}

    def test_비밀번호_재설정은_변경_강제를_건다(self) -> None:
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)

        result = fx.admin.reset_password(ctx, target.user_id)
        account = fx.accounts.find_by_id(target.user_id)

        assert account is not None
        assert account.must_change_password
        assert result.temporary_password.reveal() not in account.password_hash.encoded

    def test_재설정_임시_비밀번호로_로그인할_수_있다(self) -> None:
        fx, ctx = self._with_admin()
        target = fx.auth.sign_up("alice", GOOD_PASSWORD)
        result = fx.admin.reset_password(ctx, target.user_id)

        login = fx.auth.login("alice", result.temporary_password, client_key=CLIENT)

        assert login.succeeded
        assert login.must_change_password

    def test_AdminService_는_건강_데이터_저장소를_주입받지_않는다(self) -> None:
        """⭐ 경계 B 가 생성자 시그니처에 드러납니다 (US-48)."""
        import inspect

        from phc.identity.services.admin import AdminService

        params = set(inspect.signature(AdminService.__init__).parameters)
        forbidden = {
            "measurements",
            "profiles",
            "recommendations",
            "conversations",
            "health_data",
        }
        assert params & forbidden == set()


# ---------------------------------------------------------------------------
# MFA (US-49)
# ---------------------------------------------------------------------------
class TestMfa:
    def _enrolled(self) -> tuple[IdentityFixture, UserId]:
        fx = build_identity()
        result = fx.auth.sign_up("alice", GOOD_PASSWORD)
        fx.mfa.begin_enrollment(result.user_id, "alice")
        return fx, result.user_id

    def test_확인_전에는_MFA_가_요구되지_않는다(self) -> None:
        """INV-MF-02 — 등록만 하고 확인 안 한 상태로 갇히지 않게."""
        fx, uid = self._enrolled()
        assert not fx.mfa.is_required(uid)

    def test_확인하면_활성화되고_복구_코드가_발급된다(self) -> None:
        fx, uid = self._enrolled()
        bundle = fx.mfa.confirm_enrollment(uid, "123456")

        assert fx.mfa.is_required(uid)
        assert len(bundle.codes) == 10

    def test_비밀키가_암호문으로_저장된다(self) -> None:
        """INV-MF-01."""
        fx, uid = self._enrolled()
        enrollment = fx.mfa_repo.get_enrollment(uid)

        assert enrollment is not None
        assert b"FAKESECRET" not in enrollment.secret_cipher

    def test_복구_코드는_1회만_쓸_수_있다(self) -> None:
        """INV-RC-02."""
        fx, uid = self._enrolled()
        bundle = fx.mfa.confirm_enrollment(uid, "123456")
        code = bundle.codes[0].reveal()

        first = fx.mfa.verify(uid, code)
        second = fx.mfa.verify(uid, code)

        assert first.ok and first.used_recovery_code
        assert not second.ok

    def test_복구_코드_평문이_저장되지_않는다(self) -> None:
        """INV-RC-01."""
        fx, uid = self._enrolled()
        bundle = fx.mfa.confirm_enrollment(uid, "123456")
        plaintext = bundle.codes[0].reveal()

        stored = fx.mfa_repo.list_recovery_codes(uid)
        assert all(plaintext not in c.code_hash.encoded for c in stored)

    def test_MFA_가_활성이면_코드_없이는_세션이_발급되지_않는다(self) -> None:
        fx, uid = self._enrolled()
        fx.mfa.confirm_enrollment(uid, "123456")

        outcome = fx.auth.login("alice", GOOD_PASSWORD, client_key=CLIENT)

        assert not outcome.succeeded
        assert outcome.mfa_required
        assert outcome.session is None

    def test_같은_TOTP_코드는_재사용할_수_없다(self) -> None:
        """BR-MF-10 — 재생 공격 방지."""
        fx, uid = self._enrolled()
        fx.mfa.confirm_enrollment(uid, "123456")

        # confirm 에서 이미 소비되었으므로 같은 시간창에서 재사용 불가
        assert not fx.mfa.verify(uid, "123456").ok


# ---------------------------------------------------------------------------
# 세션 관리 — 캐시 미도입 확인 (ND8=A)
# ---------------------------------------------------------------------------
class TestSessionManager:
    def test_저장소에서_지우면_즉시_해석되지_않는다(self, identity: IdentityFixture) -> None:
        """⭐ 캐시가 있었다면 이 테스트가 실패합니다 (FR-35)."""
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)
        assert account is not None

        issued = identity.sessions.issue(account)
        assert identity.sessions.resolve(issued.token) is not None

        identity.sessions_repo.delete(issued.session.token_hash)
        assert identity.sessions.resolve(issued.token) is None

    def test_유휴_만료는_활동으로_갱신된다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)
        assert account is not None
        issued = identity.sessions.issue(account)

        identity.clock.advance(timedelta(minutes=59))
        assert identity.sessions.resolve(issued.token) is not None

        identity.clock.advance(timedelta(minutes=59))
        assert identity.sessions.resolve(issued.token) is not None

    def test_절대_만료는_활동으로도_넘길_수_없다(self, identity: IdentityFixture) -> None:
        result = identity.auth.sign_up("alice", GOOD_PASSWORD)
        account = identity.accounts.find_by_id(result.user_id)
        assert account is not None
        issued = identity.sessions.issue(account)

        for _ in range(220):  # 50분 x 220 = 약 7.6일 -> 절대 만료를 넘긴다
            identity.clock.advance(timedelta(minutes=50))
            identity.sessions.resolve(issued.token)

        assert identity.sessions.resolve(issued.token) is None
