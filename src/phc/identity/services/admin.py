"""관리자 계정 관리 (S25) — US-47 · FR-38 · FR-40.

⭐ **이 클래스의 생성자에 무엇이 없는지가 핵심입니다.**

    주입되는 것: AccountRepositoryPort · SessionManager · RoleAuthorizer
                 · PasswordHasherPort · AuditTrailPort · AlertDispatcher
    주입되지 않는 것: 건강 데이터 · 추천 · 대화 이력 리포지토리

    관리자 기능에서 타인의 건강 데이터로 가는 호출 경로가 **존재하지
    않습니다** (FR-39, US-48, 경계 B).

    ``identity`` 모듈이 ``healthdata`` · ``advisory`` 를 import 할 수 없다는
    계약 C2 가 이것을 기계적으로 강제합니다 — 나중에 누가 편의상 주입하려
    해도 import 단계에서 CI 가 막습니다.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final

from phc.identity.domain.account import Account, AccountSummary
from phc.identity.ports.password import PasswordHasherPort
from phc.identity.ports.repositories import AccountRepositoryPort
from phc.identity.services.authorization import RoleAuthorizer
from phc.identity.services.sessions import SessionManager
from phc.operations.domain.alert import AlertKind
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.ports.audit import AuditTrailPort
from phc.operations.services.alerting import AlertDispatcher
from phc.shared import (
    AuthContext,
    ClockPort,
    DomainError,
    PolicyViolationError,
    Role,
    SecretStr,
    UserId,
)

__all__ = ["AdminService", "PasswordResetResult"]

#: 재설정 임시 비밀번호 엔트로피 >= 96비트 (NFR-1A-18).
_TEMP_PASSWORD_BYTES: Final = 18


@dataclass(frozen=True, slots=True)
class PasswordResetResult:
    """재설정 결과. 임시 비밀번호는 화면에 **1회만** 표시되고 재조회할 수 없습니다."""

    target: UserId
    temporary_password: SecretStr


class AdminService:
    def __init__(
        self,
        *,
        accounts: AccountRepositoryPort,
        sessions: SessionManager,
        roles: RoleAuthorizer,
        hasher: PasswordHasherPort,
        audit: AuditTrailPort,
        alerts: AlertDispatcher,
        clock: ClockPort,
    ) -> None:
        self._accounts = accounts
        self._sessions = sessions
        self._roles = roles
        self._hasher = hasher
        self._audit = audit
        self._alerts = alerts
        self._clock = clock

    # ------------------------------------------------------------------ 조회
    def list_accounts(self, ctx: AuthContext) -> list[AccountSummary]:
        """계정 목록 (FR-38).

        ⭐ ``AccountSummary`` 에는 건강 데이터 필드도, ``password_hash`` 도
        없습니다 (BR-AD-02, BR-AD-09). 관리자 화면이 표현할 수 있는 것의
        상한이 그 타입입니다.
        """
        self._roles.require_admin(ctx, target_ref="accounts:list")
        return [account.summary() for account in self._accounts.list_all()]

    # -------------------------------------------------------------- 역할 변경
    def set_role(self, ctx: AuthContext, target: UserId, role: Role) -> None:
        self._roles.require_admin(ctx, target_ref=f"account:{target}")
        account = self._require_account(target)

        if account.role is role:
            return

        # ⭐ 관리자 0명 방지 (BR-AD-03, INV-AC-03)
        if account.is_active_admin and role is not Role.ADMIN:
            self._guard_last_admin(target)

        now = self._clock.now()
        self._accounts.save(account.with_role(role, now=now))
        # 권한이 바뀌면 기존 세션의 AuthContext 가 낡습니다 (BR-AD-04).
        self._sessions.revoke_all_for(target)

        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.ROLE_CHANGED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=ctx.subject_id,
                actor_role=ctx.role,
                target_ref=f"account:{target}",
                detail={"before": account.role.value, "after": role.value},
            )
        )
        self._alerts.raise_immediate(
            AlertKind.PRIVILEGE_CHANGED,
            "계정 역할이 변경되었습니다.",
            context={"target": str(target), "after": role.value},
        )

    # ------------------------------------------------------------ 활성 상태
    def set_active(self, ctx: AuthContext, target: UserId, active: bool) -> None:
        self._roles.require_admin(ctx, target_ref=f"account:{target}")
        account = self._require_account(target)

        if account.is_active is active:
            return

        if account.is_active_admin and not active:
            self._guard_last_admin(target)

        now = self._clock.now()
        self._accounts.save(account.with_active(active, now=now))
        if not active:
            self._sessions.revoke_all_for(target)

        event = AuditEventType.ACCOUNT_ACTIVATED if active else AuditEventType.ACCOUNT_DEACTIVATED
        self._audit.append(
            AuditEntry(
                event_type=event,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=ctx.subject_id,
                actor_role=ctx.role,
                target_ref=f"account:{target}",
            )
        )
        if not active:
            self._alerts.raise_immediate(
                AlertKind.ACCOUNT_DEACTIVATED,
                "계정이 비활성화되었습니다.",
                context={"target": str(target)},
            )

    # ------------------------------------------------------- 비밀번호 재설정
    def reset_password(self, ctx: AuthContext, target: UserId) -> PasswordResetResult:
        """관리자에 의한 재설정 (FR-40).

        이메일 발송이 Out of Scope 이므로 관리자가 대신 재설정합니다.
        임시 비밀번호는 **1회만** 반환되고, 대상 계정에 변경 강제가 걸립니다.
        """
        self._roles.require_admin(ctx, target_ref=f"account:{target}")
        account = self._require_account(target)

        now = self._clock.now()
        temporary = SecretStr(secrets.token_urlsafe(_TEMP_PASSWORD_BYTES))

        self._accounts.save(
            account.with_password(self._hasher.hash(temporary), now=now, must_change=True)
        )
        self._sessions.revoke_all_for(target)

        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.PASSWORD_RESET_BY_ADMIN,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=ctx.subject_id,
                actor_role=ctx.role,
                target_ref=f"account:{target}",
                # ⚠ 임시 비밀번호를 담지 않습니다. detail 이 Redactable 타입이라
                #   SecretStr 은 애초에 들어갈 수 없습니다.
            )
        )
        self._alerts.raise_immediate(
            AlertKind.PASSWORD_RESET_BY_ADMIN,
            "관리자가 계정 비밀번호를 재설정했습니다.",
            context={"target": str(target)},
        )

        return PasswordResetResult(target=target, temporary_password=temporary)

    # ------------------------------------------------------------------ 내부
    def _require_account(self, target: UserId) -> Account:
        account = self._accounts.find_by_id(target)
        if account is None:
            raise DomainError("account_not_found", "계정을 찾을 수 없습니다.")
        return account

    def _guard_last_admin(self, target: UserId) -> None:
        """마지막 활성 관리자를 잃는 변경을 거부한다 (BR-AD-03).

        ⚠ 화면에서 버튼을 비활성화하는 것은 안내일 뿐입니다. 실제 거부는
        여기서 합니다 — 클라이언트 측 숨김에 의존하지 않습니다 (NFR-47).
        """
        if self._accounts.count_active_admins() <= 1:
            raise PolicyViolationError(
                "last_admin",
                "시스템에 관리자가 0명이 되는 변경은 할 수 없습니다.",
                detail=f"target={target}",
            )
