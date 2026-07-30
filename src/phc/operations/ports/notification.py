"""알림 채널 포트 (ND2=A).

1A 에서는 콘솔 알림 센터 어댑터 하나만 구현합니다. 포트를 두는 이유는
향후 웹훅·데스크톱 알림을 **어댑터 추가만으로** 붙일 수 있게 하기 위함입니다.

⚠ 알림 발송 실패는 본 작업을 되돌리지 않습니다. 반면 **감사 기록 실패는 본
   작업을 실패시킵니다** (BR-AU-08). 둘의 취급이 다릅니다 —
   감사는 "일어난 일의 기록"이고 알림은 "주의 환기"이기 때문입니다.
"""

from __future__ import annotations

from typing import Protocol

from phc.operations.domain.alert import Alert

__all__ = ["NotificationChannelPort"]


class NotificationChannelPort(Protocol):
    """알림 전달 채널."""

    @property
    def name(self) -> str: ...

    def send(self, alert: Alert) -> None:
        """알림을 전달한다.

        실패해도 예외를 밖으로 던지지 않고 내부에서 로깅합니다.
        알림 전달 실패가 본 작업을 실패시켜서는 안 됩니다.
        """
        ...
