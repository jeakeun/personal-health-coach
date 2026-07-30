"""operations 포트.

⭐ ``AuditTrailPort`` 에 **갱신·삭제 연산이 없습니다.** "구현하지 않았다" 가
아니라 "인터페이스에 존재하지 않는다" 입니다 (NFR-10, BR-AU-01).

⭐ ``JobQueuePort`` 와 ``JobHandler`` 가 DIP 로 순환 의존을 해소합니다.
   ``operations`` 는 ``JobHandler`` 포트만 알고, ``healthdata``(1B)가 그것을
   구현·등록합니다. ``operations`` 는 ``healthdata`` 를 모릅니다.
"""

from __future__ import annotations

from phc.operations.ports.alert_store import AlertStorePort
from phc.operations.ports.audit import AuditFilter, AuditTrailPort
from phc.operations.ports.backup_store import BackupStorePort
from phc.operations.ports.job_queue import JobHandler, JobHandlerRegistry, JobQueuePort
from phc.operations.ports.notification import NotificationChannelPort

__all__ = [
    "AlertStorePort",
    "AuditFilter",
    "AuditTrailPort",
    "BackupStorePort",
    "JobHandler",
    "JobHandlerRegistry",
    "JobQueuePort",
    "NotificationChannelPort",
]
