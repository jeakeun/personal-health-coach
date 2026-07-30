"""1차 인증 통과 후 MFA 입력까지의 임시 상태 (S32/S33).

MFA 화면의 진입 조건은 "1차 인증 통과 + **세션 미발급**" 입니다
(`frontend-components.md` §4.4). 세션이 없으므로 두 요청 사이의 상태를 둘 곳이
따로 필요합니다.

⚠ **정직한 기재 — 이 저장소는 평문 비밀번호를 잠시 들고 있습니다.**

    `AuthService.login` 은 ``(사용자명, 비밀번호, mfa_code)`` 를 한 번에 받는
    2단계 호출 형태입니다 (`frontend-components.md` §6 엔드포인트 매핑).
    따라서 MFA 코드가 도착했을 때 비밀번호를 다시 넘겨야 합니다.

    선택지는 둘이었습니다.
      (a) 여기서 자격증명을 짧게 보관한다  ← 채택
      (b) `identity` 에 ``complete_mfa`` 를 추가해 비밀번호 없이 완료한다

    (b)가 더 낫지만 승인된 모듈의 공개 계약을 표현 계층 사정으로 바꾸는 것이라
    임의로 하지 않았습니다. 대신 노출을 좁혔습니다 — **TTL 3분 · 1회용 ·
    보관 상한 · 프로세스 메모리 한정(디스크·로그·쿠키 어디에도 남지 않음)**.
    발견 사항 F-24 로 기록했고, ``complete_mfa`` 도입을 권고합니다.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from phc.shared import SecretStr

__all__ = ["PENDING_MFA_TTL", "PendingLogin", "PendingMfaStore"]

#: 짧게 유지합니다. 인증 앱에서 코드를 읽어 입력하기에 충분하고,
#: 자격증명이 메모리에 머무는 시간을 최소화합니다.
PENDING_MFA_TTL: Final = timedelta(minutes=3)

#: 동시 대기 상한. 넘으면 가장 오래된 것부터 버립니다.
MAX_PENDING: Final = 64


@dataclass(frozen=True, slots=True)
class PendingLogin:
    """1차 인증을 통과한 로그인 시도."""

    display_name: str
    password: SecretStr
    client_key: str
    expires_at: datetime

    def __redacted_repr__(self) -> str:
        """⚠ 사용자명도 비밀번호도 담지 않습니다."""
        return "PendingLogin(***)"


class PendingMfaStore:
    """MFA 대기 상태. **프로세스 메모리에만** 존재합니다."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, PendingLogin] = {}

    def put(
        self,
        *,
        display_name: str,
        password: SecretStr,
        client_key: str,
        now: datetime,
    ) -> str:
        """대기 상태를 저장하고 조회용 토큰을 반환한다."""
        token = secrets.token_urlsafe(32)
        entry = PendingLogin(
            display_name=display_name,
            password=password,
            client_key=client_key,
            expires_at=now + PENDING_MFA_TTL,
        )
        with self._lock:
            self._purge(now)
            if len(self._entries) >= MAX_PENDING:
                oldest = min(self._entries, key=lambda key: self._entries[key].expires_at)
                del self._entries[oldest]
            self._entries[token] = entry
        return token

    def take(self, token: str | None, *, now: datetime) -> PendingLogin | None:
        """⭐ **1회용** — 꺼내면 사라집니다.

        재사용을 허용하면 토큰 하나로 MFA 코드를 무제한 시도할 수 있게 됩니다.
        """
        if not token:
            return None
        with self._lock:
            self._purge(now)
            entry = self._entries.pop(token, None)
        if entry is None or entry.expires_at <= now:
            return None
        return entry

    def peek(self, token: str | None, *, now: datetime) -> bool:
        """대기 상태가 아직 살아 있는가. 화면 렌더링 판정용이며 **소비하지 않습니다**."""
        if not token:
            return False
        with self._lock:
            entry = self._entries.get(token)
        return entry is not None and entry.expires_at > now

    def discard(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._entries.pop(token, None)

    def _purge(self, now: datetime) -> None:
        """만료 항목 제거. 호출자가 잠금을 보유한 상태여야 합니다."""
        for token in [t for t, e in self._entries.items() if e.expires_at <= now]:
            del self._entries[token]

    def size(self) -> int:
        with self._lock:
            return len(self._entries)
