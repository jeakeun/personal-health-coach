"""알림 발송 (S14) — L-10 `AlertDispatcher`.

임계치 (ND3=A):
    즉시 — 인가 위반 · 권한 변경 · 백업 실패 · 관리자 잠금 각 1회
    누적 — 동일 계정 로그인 실패 10분 10회 / 전체 10분 30회

⚠ 알림 발송 실패는 본 작업을 되돌리지 않습니다.
   반면 **감사 기록 실패는 본 작업을 실패시킵니다** (BR-AU-08).
   감사는 "일어난 일의 기록" 이고 알림은 "주의 환기" 이므로 취급이 다릅니다.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

from phc.operations.domain.alert import (
    IMMEDIATE_RULES,
    WINDOWED_RULES,
    Alert,
    AlertId,
    AlertKind,
)
from phc.operations.ports.alert_store import AlertStorePort
from phc.operations.ports.notification import NotificationChannelPort
from phc.operations.services.logging import get_logger
from phc.shared import ClockPort, Redactable

__all__ = ["AlertDispatcher"]

_log = get_logger(__name__)

#: 같은 종류의 알림을 이 간격 안에 반복 발송하지 않습니다.
#: 즉시 알림도 폭주하면 무시되기 시작하므로, 저장은 하되 발송만 억제합니다.
DEDUP_WINDOW: Final = timedelta(minutes=5)


class AlertDispatcher:
    """임계치를 판정하고 채널로 알림을 보낸다."""

    def __init__(
        self,
        *,
        store: AlertStorePort,
        channels: list[NotificationChannelPort],
        clock: ClockPort,
    ) -> None:
        self._store = store
        self._channels = channels
        self._clock = clock
        self._windowed = {rule.kind: rule for rule in WINDOWED_RULES}

    # -- 즉시 알림 -----------------------------------------------------------
    def raise_immediate(
        self,
        kind: AlertKind,
        summary: str,
        *,
        context: dict[str, Redactable] | None = None,
    ) -> Alert | None:
        """1회 발생으로 알린다.

        정상 운영에서 드물어야 하는 사건이므로 놓치지 않습니다.
        """
        severity = IMMEDIATE_RULES.get(kind)
        if severity is None:
            raise ValueError(f"즉시 알림 대상이 아닙니다: {kind.value}")

        return self._emit(kind, severity, summary, context or {})

    # -- 누적 알림 -----------------------------------------------------------
    def raise_if_over_threshold(
        self,
        kind: AlertKind,
        occurrences_in_window: int,
        *,
        summary: str,
        context: dict[str, Redactable] | None = None,
    ) -> Alert | None:
        """시간 창 안의 발생 횟수가 임계를 넘으면 알린다.

        오타로도 발생하는 사건(로그인 실패 등)에 사용합니다. 알림 피로를
        막기 위한 장치입니다.
        """
        rule = self._windowed.get(kind)
        if rule is None:
            raise ValueError(f"누적 알림 대상이 아닙니다: {kind.value}")
        if occurrences_in_window < rule.threshold:
            return None

        enriched: dict[str, Redactable] = dict(context or {})
        enriched["occurrences"] = str(occurrences_in_window)
        enriched["threshold"] = str(rule.threshold)
        enriched["window_minutes"] = str(int(rule.window.total_seconds() // 60))

        return self._emit(kind, rule.severity, summary, enriched)

    # -- 내부 ---------------------------------------------------------------
    def _emit(
        self,
        kind: AlertKind,
        severity: object,
        summary: str,
        context: dict[str, Redactable],
    ) -> Alert | None:
        now = self._clock.now()

        alert = Alert(
            id=AlertId.generate(),
            kind=kind,
            severity=severity,  # type: ignore[arg-type]
            raised_at=now,
            summary=summary,
            context=context,
        )

        # 저장은 항상 합니다. 발송만 중복 억제합니다 —
        # 억제된 알림도 대시보드에는 남아야 나중에 셀 수 있습니다.
        self._store.save(alert)

        last = self._store.last_raised_at(kind)
        suppressed = last is not None and (now - last) < DEDUP_WINDOW and last != now

        if not suppressed:
            self._deliver(alert)

        _log.info(
            "alert.raised",
            kind=kind,
            severity=alert.severity,
            delivered=not suppressed,
        )
        return alert

    def _deliver(self, alert: Alert) -> None:
        for channel in self._channels:
            try:
                channel.send(alert)
            except Exception as exc:  # 광범위 포착 사유: 알림 실패가 본 작업을 막지 않게
                _log.error(
                    "alert.delivery_failed",
                    channel=channel.name,
                    kind=alert.kind,
                    error_type=type(exc).__name__,
                )
