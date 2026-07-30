"""감사 도메인 — append-only 기록.

NFR-10 / SECURITY-13:
    애플리케이션이 자신의 감사 로그를 삭제·수정할 수 없어야 합니다.
    이 모듈과 ``AuditTrailPort`` 에는 **갱신·삭제 연산이 정의되어 있지
    않습니다**. "구현하지 않았다"가 아니라 "인터페이스에 없다" 입니다.

BR-AU-02:
    ``detail`` 은 ``Redactable`` 만 담을 수 있습니다. ``SecretStr`` ·
    ``PasswordHash`` · ``SessionToken`` 은 타입 수준에서 진입할 수 없습니다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from phc.shared import Redactable, Role, UserId

__all__ = ["ALERT_WORTHY_EVENTS", "AuditEntry", "AuditEventType", "AuditOutcome"]


class AuditEventType(StrEnum):
    """감사 대상 이벤트 (domain-entities.md §3).

    목록에 없는 이벤트를 기록하지 않고, 목록에 있는 이벤트를 빠뜨리지 않습니다.
    """

    ACCOUNT_CREATED = "account_created"
    ACCOUNT_CREATE_REJECTED = "account_create_rejected"
    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    LOGIN_BLOCKED = "login_blocked"
    LOGOUT = "logout"
    # 린트 예외: 이름에 PASSWORD 가 들어가 하드코딩 비밀번호로 오인됩니다.
    # 실제로는 감사 이벤트 종류를 나타내는 슬러그입니다.
    PASSWORD_CHANGED = "password_changed"  # noqa: S105
    PASSWORD_RESET_BY_ADMIN = "password_reset_by_admin"  # noqa: S105
    ROLE_CHANGED = "role_changed"
    ACCOUNT_ACTIVATED = "account_activated"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    ADMIN_BOOTSTRAPPED = "admin_bootstrapped"
    MFA_ENROLLED = "mfa_enrolled"
    MFA_DISABLED = "mfa_disabled"
    MFA_RECOVERY_CODE_USED = "mfa_recovery_code_used"
    #: ⭐ US-48 의 인수 기준("거부가 감사 로그에 기록된다")을 직접 담당합니다.
    AUTHZ_DENIED = "authz_denied"
    BACKUP_SUCCEEDED = "backup_succeeded"
    BACKUP_FAILED = "backup_failed"
    RESTORE_PERFORMED = "restore_performed"
    AUDIT_ARCHIVED = "audit_archived"

    def __redacted_repr__(self) -> str:
        return self.value


class AuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"

    def __redacted_repr__(self) -> str:
        return self.value


#: 알림 대상 이벤트 (nfr-design-patterns.md §5.5).
#: 정상 운영에서 드물어야 하는 사건들이므로 1회도 놓치지 않습니다.
ALERT_WORTHY_EVENTS: frozenset[AuditEventType] = frozenset(
    {
        AuditEventType.AUTHZ_DENIED,
        AuditEventType.ROLE_CHANGED,
        AuditEventType.ACCOUNT_DEACTIVATED,
        AuditEventType.BACKUP_FAILED,
        AuditEventType.MFA_RECOVERY_CODE_USED,
        AuditEventType.PASSWORD_RESET_BY_ADMIN,
    }
)


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """감사 기록 한 건.

    ``seq`` 는 저장 시점에 저장소가 부여합니다 (단조 증가, 결번은 변조 신호).
    """

    event_type: AuditEventType
    outcome: AuditOutcome
    occurred_at: datetime
    actor_user_id: UserId | None = None
    actor_role: Role | None = None
    target_ref: str | None = None
    correlation_id: str | None = None
    #: ⚠ Redactable 만 허용. 민감 타입은 여기 들어올 수 없습니다 (INV-AU-02).
    detail: dict[str, Redactable] = field(default_factory=dict)
    #: 저장 후 부여됨. 미저장 엔트리는 None.
    seq: int | None = None

    @property
    def is_alert_worthy(self) -> bool:
        return self.event_type in ALERT_WORTHY_EVENTS

    def __redacted_repr__(self) -> str:
        return (
            f"AuditEntry(seq={self.seq}, event={self.event_type.value}, "
            f"outcome={self.outcome.value})"
        )
