"""알림 저장소 포트.

알림은 확인 표시 전까지 대시보드에 남습니다 (ND2=A).
자동 소멸하는 알림은 없던 알림과 같습니다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from phc.operations.domain.alert import Alert, AlertId, AlertKind

__all__ = ["AlertStorePort"]


class AlertStorePort(Protocol):
    def save(self, alert: Alert) -> None: ...

    def get(self, alert_id: AlertId) -> Alert | None: ...

    def list_open(self, *, limit: int = 100) -> list[Alert]:
        """미확인 알림을 최신순으로."""
        ...

    def last_raised_at(self, kind: AlertKind) -> datetime | None:
        """같은 종류의 마지막 발생 시각. 중복 알림 억제 판정에 사용됩니다."""
        ...
