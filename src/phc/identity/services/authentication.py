"""인증과 오케스트레이션 (S20 · S25).

⭐ 이 모듈의 설계 중심은 **응답 동일성**입니다 (BR-TH-10~13).

    계정 없음      ─┐
    비밀번호 틀림   ├─> 동일 본문 · 동일 상태코드 · 동일 시간대
    계정 비활성     │
    잠금 상태      ─┘

    시간 동일성은 더미 해시 검증(BR-TH-12)과 누적 지연(BR-TH-02)으로 맞춥니다.

    **한계 인정**: DB 조회 경로 차이로 미세 편차는 남습니다. 완전한 상수
    시간을 주장하지 않으며, 지연이 편차를 실용적으로 덮는 구조입니다
    (NFR-1A-24 는 중앙값 차이 10% 이내로 판정).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from phc.identity.domain.account import Account
from phc.identity.domain.throttle import AttemptOutcome, ThrottleKey
from phc.identity.ports.password import PasswordHasherPort
from phc.identity.ports.repositories import AccountRepositoryPort
from phc.identity.services.mfa import MfaEnroller
from phc.identity.services.passwords import PasswordPolicy
from phc.identity.services.sessions import IssuedSession, SessionManager
from phc.identity.services.throttling import LoginThrottle
from phc.operations.domain.alert import AlertKind
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.ports.audit import AuditTrailPort
from phc.operations.services.alerting import AlertDispatcher
from phc.operations.services.metrics import MetricName, MetricsRegistry
from phc.shared import (
    AuthContext,
    ClockPort,
    ConflictError,
    DomainError,
    PolicyViolationError,
    Role,
    SecretStr,
    SessionToken,
    UserId,
    Username,
)

__all__ = ["AuthService", "LoginOutcome", "SignUpResult"]

#: 로그인 실패 누적 알림 창 (ND3=A).
_FAILURE_WINDOW: Final = timedelta(minutes=10)

#: 어떤 실패에도 동일하게 반환되는 문구 (BR-TH-10).
_GENERIC_LOGIN_FAILURE: Final = "사용자명 또는 비밀번호가 올바르지 않습니다."


@dataclass(frozen=True, slots=True)
class SignUpResult:
    user_id: UserId


@dataclass(frozen=True, slots=True)
class LoginOutcome:
    """로그인 결과.

    ``mfa_required`` 인 경우 세션은 **발급되지 않습니다** — 2차 인증을
    통과해야 세션이 생깁니다.
    """

    succeeded: bool
    mfa_required: bool = False
    session: IssuedSession | None = None
    must_change_password: bool = False
    message: str | None = None


class AuthService:
    """회원가입 · 로그인 · 로그아웃 · 비밀번호 변경."""

    def __init__(
        self,
        *,
        accounts: AccountRepositoryPort,
        hasher: PasswordHasherPort,
        policy: PasswordPolicy,
        throttle: LoginThrottle,
        sessions: SessionManager,
        mfa: MfaEnroller,
        audit: AuditTrailPort,
        alerts: AlertDispatcher,
        clock: ClockPort,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._accounts = accounts
        self._hasher = hasher
        self._policy = policy
        self._throttle = throttle
        self._sessions = sessions
        self._mfa = mfa
        self._audit = audit
        self._alerts = alerts
        self._clock = clock
        self._metrics = metrics

    # ------------------------------------------------------------------ 가입
    def sign_up(self, display_name: str, password: SecretStr) -> SignUpResult:
        """자유 가입. 역할은 항상 ``USER`` 입니다 (F7=A, BR-SU-01/02)."""
        now = self._clock.now()

        try:
            username = Username.parse(display_name)
        except ValueError as exc:
            self._audit_rejection("invalid_username")
            raise PolicyViolationError("invalid_username", str(exc)) from exc

        if username.is_reserved():
            # 자유 가입이므로 부트스트랩 전 admin 선점을 막아야 합니다 (BR-BS-10).
            self._audit_rejection("reserved_username")
            raise PolicyViolationError(
                "reserved_username", "해당 사용자명으로는 가입할 수 없습니다."
            )

        result = self._policy.validate(password)
        if not result.passes:
            self._audit_rejection(result.reason_code or "policy")
            raise PolicyViolationError(
                result.reason_code or "policy_violation",
                result.message or "비밀번호 정책을 만족하지 않습니다.",
            )

        # 사전 조회는 사용자 경험용입니다. 최종 방어는 저장소 유일 제약입니다.
        if self._accounts.find_by_username(username) is not None:
            self._audit_rejection("username_taken")
            raise ConflictError("username_taken", "해당 사용자명으로는 가입할 수 없습니다.")

        account = Account(
            id=UserId.generate(),
            username=username,
            display_name=display_name.strip(),
            password_hash=self._hasher.hash(password),
            role=Role.USER,
            is_active=True,
            must_change_password=False,
            created_at=now,
            updated_at=now,
        )
        self._accounts.save(account)

        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.ACCOUNT_CREATED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=account.id,
                actor_role=account.role,
                target_ref=f"account:{account.id}",
            )
        )
        return SignUpResult(user_id=account.id)

    # ---------------------------------------------------------------- 로그인
    def login(
        self,
        display_name: str,
        password: SecretStr,
        *,
        client_key: str,
        mfa_code: str | None = None,
    ) -> LoginOutcome:
        normalized = Username.normalize(display_name)
        key = ThrottleKey(username_normalized=normalized, client_key=client_key)

        decision = self._throttle.check(key)
        if not decision.allowed:
            self._throttle.apply_delay(decision)
            self._record(AuditEventType.LOGIN_BLOCKED, AuditOutcome.DENIED, normalized)
            self._count(MetricName.LOGIN_BLOCKED)
            # ⚠ locked_until 을 노출하지 않습니다 (BR-TH-13).
            return LoginOutcome(succeeded=False, message=_GENERIC_LOGIN_FAILURE)

        account = self._lookup(normalized)

        if account is None:
            # ⭐ 계정이 없어도 같은 시간을 씁니다 (BR-TH-12).
            self._hasher.dummy_verify()
            return self._fail(key, normalized, AttemptOutcome.BAD_CREDENTIALS)

        if not self._hasher.verify(password, account.password_hash):
            return self._fail(key, normalized, AttemptOutcome.BAD_CREDENTIALS)

        if not account.can_sign_in:
            # 비활성 계정도 동일 응답 — 계정 존재가 드러나지 않게.
            return self._fail(key, normalized, AttemptOutcome.INACTIVE)

        if self._mfa.is_required(account.id):
            if mfa_code is None:
                self._throttle.apply_delay(decision)
                return LoginOutcome(succeeded=False, mfa_required=True)
            if not self._mfa.verify(account.id, mfa_code).ok:
                return self._fail(key, normalized, AttemptOutcome.MFA_FAILED)

        return self._succeed(account, key, password)

    def _succeed(self, account: Account, key: ThrottleKey, password: SecretStr) -> LoginOutcome:
        now = self._clock.now()

        # 파라미터가 상향되었으면 이 시점에 재해시합니다 (BR-PW-07).
        if self._hasher.needs_rehash(account.password_hash):
            account = account.with_password(
                self._hasher.hash(password),
                now=now,
                must_change=account.must_change_password,
            )

        self._throttle.record_success(key)
        session = self._sessions.issue(account)
        self._accounts.save(account.with_login(now=now))

        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.LOGIN_SUCCEEDED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=account.id,
                actor_role=account.role,
            )
        )
        self._count(MetricName.LOGIN_SUCCESS)

        return LoginOutcome(
            succeeded=True,
            session=session,
            must_change_password=account.must_change_password,
        )

    def _fail(self, key: ThrottleKey, normalized: str, outcome: AttemptOutcome) -> LoginOutcome:
        state = self._throttle.record_failure(key, outcome)
        self._record(AuditEventType.LOGIN_FAILED, AuditOutcome.FAILED, normalized)
        self._count(MetricName.LOGIN_FAILURE)
        self._maybe_alert(normalized, state_locked=state.locked_until is not None)
        # 지연은 갱신된 실패 횟수 기준으로 다시 계산해 적용합니다.
        self._throttle.apply_delay(state.decide(self._clock.now()))
        return LoginOutcome(succeeded=False, message=_GENERIC_LOGIN_FAILURE)

    # -------------------------------------------------------------- 로그아웃
    def logout(self, token: SessionToken, ctx: AuthContext) -> None:
        self._sessions.revoke(token)
        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.LOGOUT,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=self._clock.now(),
                actor_user_id=ctx.subject_id,
                actor_role=ctx.role,
            )
        )

    # ---------------------------------------------------------- 비밀번호 변경
    def change_password(self, ctx: AuthContext, current: SecretStr, new: SecretStr) -> None:
        """본인 비밀번호 변경 (US-50).

        ⭐ 성공 시 **자기 세션까지 포함해 전량 무효화**합니다 (BR-PW-06).
        유출 의심 상황에서 비밀번호를 바꾸는 것이므로, "다른 기기만 끊고
        나는 유지" 는 목적과 맞지 않습니다.
        """
        account = self._accounts.find_by_id(ctx.subject_id)
        if account is None:
            raise DomainError("account_not_found", "계정을 찾을 수 없습니다.")

        if not self._hasher.verify(current, account.password_hash):
            raise PolicyViolationError(
                "current_password_mismatch", "현재 비밀번호가 올바르지 않습니다."
            )

        if current == new:
            raise PolicyViolationError(
                "password_unchanged", "이전과 다른 비밀번호를 사용해 주세요."
            )

        result = self._policy.validate(new)
        if not result.passes:
            raise PolicyViolationError(
                result.reason_code or "policy_violation",
                result.message or "비밀번호 정책을 만족하지 않습니다.",
            )

        now = self._clock.now()
        self._accounts.save(
            account.with_password(self._hasher.hash(new), now=now, must_change=False)
        )
        self._sessions.revoke_all_for(account.id)
        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.PASSWORD_CHANGED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=account.id,
                actor_role=account.role,
            )
        )

    # ------------------------------------------------------------------ 내부
    def _lookup(self, normalized: str) -> Account | None:
        return self._accounts.find_by_username(Username(normalized))

    def _record(self, event: AuditEventType, outcome: AuditOutcome, normalized: str) -> None:
        self._audit.append(
            AuditEntry(
                event_type=event,
                outcome=outcome,
                occurred_at=self._clock.now(),
                detail={"username": normalized},
            )
        )

    def _count(self, name: str) -> None:
        if self._metrics is not None:
            self._metrics.increment(name)

    def _maybe_alert(self, normalized: str, *, state_locked: bool) -> None:
        per_account = self._throttle.failures_in_window(normalized, _FAILURE_WINDOW)
        self._alerts.raise_if_over_threshold(
            AlertKind.LOGIN_FAILURE_BURST_ACCOUNT,
            per_account,
            summary="동일 계정에 로그인 실패가 반복되고 있습니다.",
            context={"username": normalized},
        )

        overall = self._throttle.all_failures_in_window(_FAILURE_WINDOW)
        self._alerts.raise_if_over_threshold(
            AlertKind.LOGIN_FAILURE_BURST_GLOBAL,
            overall,
            summary="전체 로그인 실패가 급증하고 있습니다.",
        )

        if state_locked:
            account = self._lookup(normalized)
            if account is not None and account.role is Role.ADMIN:
                self._alerts.raise_immediate(
                    AlertKind.ADMIN_LOCKED,
                    "관리자 계정이 잠겼습니다.",
                    context={"username": normalized},
                )

    def _audit_rejection(self, reason: str) -> None:
        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.ACCOUNT_CREATE_REJECTED,
                outcome=AuditOutcome.DENIED,
                occurred_at=self._clock.now(),
                # ⚠ 입력 비밀번호는 담지 않습니다. 사유 코드만.
                detail={"reason": reason},
            )
        )
