"""TOTP 포트 (NFR-44, F5=A).

RFC 6238. 외부 의존이 없고 표준이라 로컬 실행 환경에 맞습니다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from phc.shared import SecretStr

__all__ = ["TotpPort"]


class TotpPort(Protocol):
    def generate_secret(self) -> SecretStr:
        """새 비밀키를 만든다. 평문은 등록 응답에 **1회만** 실립니다."""
        ...

    def provisioning_uri(self, secret: SecretStr, account_name: str) -> str:
        """인증 앱 등록용 URI (QR 코드 원본)."""
        ...

    def verify(self, secret: SecretStr, code: str, *, now: datetime) -> bool:
        """코드를 검증한다.

        구현체는 시간창 재사용을 거부해야 합니다 (BR-MF-10, 재생 공격 방지).
        """
        ...
