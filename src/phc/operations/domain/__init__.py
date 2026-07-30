"""operations 도메인 — 작업 큐 · 감사 · 백업 · 알림.

⚠ 이 패키지는 ``sqlalchemy`` · ``fastapi`` 를 import 하지 않습니다 (계약 C4).
"""

from __future__ import annotations

from phc.operations.domain.alert import (
    IMMEDIATE_RULES,
    WINDOWED_RULES,
    Alert,
    AlertId,
    AlertKind,
    AlertSeverity,
    WindowedRule,
)
from phc.operations.domain.audit import (
    ALERT_WORTHY_EVENTS,
    AuditEntry,
    AuditEventType,
    AuditOutcome,
)
from phc.operations.domain.backup import BackupArtifact, BackupId, RetentionPolicy
from phc.operations.domain.job import (
    BACKOFF_BASE,
    Job,
    JobId,
    JobKind,
    JobSpec,
    JobState,
    JobTransitionError,
    WorkerId,
)

__all__ = [
    "ALERT_WORTHY_EVENTS",
    "BACKOFF_BASE",
    "IMMEDIATE_RULES",
    "WINDOWED_RULES",
    "Alert",
    "AlertId",
    "AlertKind",
    "AlertSeverity",
    "AuditEntry",
    "AuditEventType",
    "AuditOutcome",
    "BackupArtifact",
    "BackupId",
    "Job",
    "JobId",
    "JobKind",
    "JobSpec",
    "JobState",
    "JobTransitionError",
    "RetentionPolicy",
    "WindowedRule",
    "WorkerId",
]
