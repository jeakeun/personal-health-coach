"""콘솔 알림 채널 (ND2=A).

1A 의 유일한 알림 어댑터입니다. 알림은 ``AlertStorePort`` 에 저장되어
관리자 콘솔의 알림 센터에 표시되며, 이 어댑터는 그와 별개로 **구조화 로그**
에 남깁니다.

외부 의존이 전혀 없습니다. 이메일은 Out of Scope(SMTP 회피)이고, 웹훅은
설정에 자격증명 성격의 URL 이 들어가므로 1A 에서는 두지 않습니다.
향후 필요하면 ``NotificationChannelPort`` 구현을 추가하면 됩니다.
"""

from __future__ import annotations

from phc.operations.domain.alert import Alert, AlertSeverity
from phc.operations.services.logging import get_logger

__all__ = ["ConsoleNotificationChannel"]

_log = get_logger("phc.alert")


class ConsoleNotificationChannel:
    """구조화 로그로 알림을 남긴다."""

    @property
    def name(self) -> str:
        return "console"

    def send(self, alert: Alert) -> None:
        log_fn = {
            AlertSeverity.HIGH: _log.error,
            AlertSeverity.MEDIUM: _log.warning,
            AlertSeverity.LOW: _log.info,
        }[alert.severity]

        log_fn(
            "alert",
            kind=alert.kind,
            severity=alert.severity,
            summary=alert.summary,
            alert_id=alert.id,
            **alert.context,
        )
