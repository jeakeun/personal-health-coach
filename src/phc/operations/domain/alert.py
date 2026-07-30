"""알림 도메인 (SECURITY-14, ND2=A · ND3=A).

설계 의도:
    인가 위반 · 권한 변경 · 백업 실패는 **정상 운영에서 드물어야** 하므로
    1회도 놓치지 않습니다. 반면 로그인 실패는 오타로도 발생하므로 누적
    기준을 두어 알림 피로를 막습니다.

    잠금 임계치(10회 초과)와 알림 임계치(10회)를 맞춰
    **"잠기기 직전에 알림"** 이 되게 했습니다.

알림은 확인 표시 전까지 남습니다. 자동 소멸하지 않습니다 —
사라진 알림은 없던 알림과 같습니다.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from phc.shared import Redactable

__all__ = [
    "IMMEDIATE_RULES",
    "WINDOWED_RULES",
    "Alert",
    "AlertId",
    "AlertKind",
    "AlertSeverity",
    "WindowedRule",
]


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __redacted_repr__(self) -> str:
        return self.value


class AlertKind(StrEnum):
    AUTHZ_VIOLATION = "authz_violation"
    PRIVILEGE_CHANGED = "privilege_changed"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    BACKUP_FAILURE = "backup_failure"
    ADMIN_LOCKED = "admin_locked"
    MFA_RECOVERY_USED = "mfa_recovery_used"
    # 린트 예외: 알림 종류 슬러그이며 비밀번호가 아닙니다.
    PASSWORD_RESET_BY_ADMIN = "password_reset_by_admin"  # noqa: S105
    LOGIN_FAILURE_BURST_ACCOUNT = "login_failure_burst_account"
    LOGIN_FAILURE_BURST_GLOBAL = "login_failure_burst_global"
    JOB_REPEATED_FAILURE = "job_repeated_failure"
    UNHANDLED_ERROR_BURST = "unhandled_error_burst"

    def __redacted_repr__(self) -> str:
        return self.value


#: 1회 발생 즉시 알리는 종류와 등급.
IMMEDIATE_RULES: Final[dict[AlertKind, AlertSeverity]] = {
    AlertKind.AUTHZ_VIOLATION: AlertSeverity.HIGH,
    AlertKind.PRIVILEGE_CHANGED: AlertSeverity.HIGH,
    AlertKind.BACKUP_FAILURE: AlertSeverity.HIGH,
    AlertKind.ADMIN_LOCKED: AlertSeverity.HIGH,
    AlertKind.ACCOUNT_DEACTIVATED: AlertSeverity.MEDIUM,
    AlertKind.MFA_RECOVERY_USED: AlertSeverity.MEDIUM,
    AlertKind.PASSWORD_RESET_BY_ADMIN: AlertSeverity.MEDIUM,
}


@dataclass(frozen=True, slots=True)
class WindowedRule:
    """시간 창 안에서 임계 횟수를 넘으면 알린다."""

    kind: AlertKind
    severity: AlertSeverity
    threshold: int
    window: timedelta


#: 누적 기준 알림. 오타로도 발생하는 사건들입니다.
WINDOWED_RULES: Final[tuple[WindowedRule, ...]] = (
    WindowedRule(
        AlertKind.LOGIN_FAILURE_BURST_ACCOUNT,
        AlertSeverity.MEDIUM,
        threshold=10,
        window=timedelta(minutes=10),
    ),
    WindowedRule(
        AlertKind.LOGIN_FAILURE_BURST_GLOBAL,
        AlertSeverity.MEDIUM,
        threshold=30,
        window=timedelta(minutes=10),
    ),
    WindowedRule(
        AlertKind.JOB_REPEATED_FAILURE,
        AlertSeverity.LOW,
        threshold=3,
        window=timedelta(hours=1),
    ),
    WindowedRule(
        AlertKind.UNHANDLED_ERROR_BURST,
        AlertSeverity.MEDIUM,
        threshold=10,
        window=timedelta(minutes=10),
    ),
)


@dataclass(frozen=True, slots=True, order=True)
class AlertId:
    value: str

    @classmethod
    def generate(cls) -> AlertId:
        return cls(uuid.uuid4().hex)

    def __str__(self) -> str:
        return self.value

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Alert:
    """발생한 알림 한 건."""

    id: AlertId
    kind: AlertKind
    severity: AlertSeverity
    raised_at: datetime
    summary: str
    #: ⚠ Redactable 만. 민감값은 담기지 않습니다.
    context: dict[str, Redactable] = field(default_factory=dict)
    acknowledged_at: datetime | None = None

    @property
    def is_open(self) -> bool:
        """확인되지 않은 알림은 대시보드에 계속 남습니다."""
        return self.acknowledged_at is None

    def acknowledge(self, *, now: datetime) -> Alert:
        from dataclasses import replace

        return replace(self, acknowledged_at=now)

    def __redacted_repr__(self) -> str:
        return f"Alert(kind={self.kind.value}, severity={self.severity.value})"
