"""TOTP 어댑터 (S22, F5=A) — RFC 6238.

시간창 재사용 거부(BR-MF-10)를 위해 사용된 ``(user, counter)`` 를 기억합니다.
같은 코드를 두 번 쓰는 재생 공격을 막습니다.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Final

import pyotp

from phc.shared import SecretStr

__all__ = ["ISSUER_NAME", "PyotpTotpAdapter"]

ISSUER_NAME: Final = "Personal Health Coach"

#: TOTP 시간창 (초). 표준 30초.
_STEP_SECONDS: Final = 30

#: 앞뒤 1창까지 허용 — 기기 시계 오차 대응.
_VALID_WINDOW: Final = 1


class PyotpTotpAdapter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        #: (비밀키 지문, 카운터) — 이미 소비된 시간창
        self._consumed: set[tuple[str, int]] = set()

    def generate_secret(self) -> SecretStr:
        return SecretStr(pyotp.random_base32())

    def provisioning_uri(self, secret: SecretStr, account_name: str) -> str:
        return str(
            pyotp.TOTP(secret.reveal()).provisioning_uri(name=account_name, issuer_name=ISSUER_NAME)
        )

    def verify(self, secret: SecretStr, code: str, *, now: datetime) -> bool:
        totp = pyotp.TOTP(secret.reveal())
        if not totp.verify(code, for_time=now, valid_window=_VALID_WINDOW):
            return False

        counter = int(now.timestamp()) // _STEP_SECONDS
        fingerprint = secret.reveal()[:8]

        with self._lock:
            marker = (fingerprint, counter)
            if marker in self._consumed:
                # 같은 시간창의 코드를 두 번 쓰는 것을 거부합니다 (BR-MF-10).
                return False
            self._consumed.add(marker)
            # 오래된 표시는 버립니다 — 무한히 쌓이면 메모리가 샙니다.
            cutoff = counter - 10
            self._consumed = {m for m in self._consumed if m[1] > cutoff}

        return True
