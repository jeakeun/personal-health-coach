"""레이트 리밋 상태와 클라이언트 식별 (S32) — L-11 · `ClientKeyResolver`.

⚠ **`client_key` 의 실제 변별력에 관한 기록 (ND9=A)**

    이 앱은 ``127.0.0.1`` 에 바인딩되므로 ``remote_ip`` 가 언제나 루프백입니다.
    User-Agent 를 섞어도 같은 브라우저에서 오는 요청은 전부 같은 키가 됩니다.
    **즉 로컬 실행에서 레이트 리밋은 사실상 전역 한도로 동작합니다.**

    실질 방어는 계정 단위 스로틀(``ThrottleState`` 의 username 성분)입니다.
    이 컴포넌트가 존재하는 이유는 클라우드 이전 시 코드 변경 없이 의미를
    회복하기 위해서이며, 이 한계를 여기 적어 두는 목적은 **"레이트 리밋이
    있으니 무차별 대입에 안전하다"는 오판을 막기 위해서**입니다.
"""

from __future__ import annotations

import hashlib
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Final

__all__ = ["ClientKeyResolver", "InMemoryRateCounter", "RateLimitRule"]

#: 보관 상한. 키가 무한히 쌓이면 장시간 실행에서 메모리가 샙니다.
MAX_TRACKED_KEYS: Final = 4096


class ClientKeyResolver:
    """``hash(remote_ip + user_agent)`` (ND9=A)."""

    @staticmethod
    def resolve(remote_ip: str | None, user_agent: str | None) -> str:
        raw = f"{remote_ip or 'unknown'}|{user_agent or 'unknown'}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class RateLimitRule:
    """경로 접두사별 한도."""

    __slots__ = ("limit", "prefix", "window")

    def __init__(self, prefix: str, *, limit: int, window: timedelta) -> None:
        self.prefix = prefix
        self.limit = limit
        self.window = window


class InMemoryRateCounter:
    """슬라이딩 윈도 카운터 (L-11).

    재기동 시 초기화되는 것을 **허용합니다.** 계정 잠금과 달리 레이트 리밋은
    자원 보호 장치이지 인증 판정이 아니기 때문입니다 — 잠금 상태는 DB 에
    있습니다 (ND6=A).

    워커 스레드가 쓰지는 않지만 ASGI 워커가 여러 요청을 동시에 처리하므로
    잠금을 둡니다.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, deque[datetime]] = {}

    def hit(self, key: str, *, now: datetime, limit: int, window: timedelta) -> bool:
        """요청 1건을 기록하고 한도 내인지 반환한다.

        ⛔ 한도를 넘으면 ``False`` — 호출자는 거부해야 합니다. 이 판정은
        **적응형 해시보다 앞**에서 이루어져야 의미가 있습니다 (L-02 배치 근거).
        """
        cutoff = now - window
        with self._lock:
            if len(self._hits) > MAX_TRACKED_KEYS:
                self._evict(cutoff)

            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                return False

            bucket.append(now)
            return True

    def _evict(self, cutoff: datetime) -> None:
        """창을 벗어난 키를 정리한다. 호출자가 잠금을 보유한 상태여야 합니다."""
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] < cutoff]
        for key in stale:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
