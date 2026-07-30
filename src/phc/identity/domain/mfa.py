"""MFA 도메인 (S17, F5=A) — TOTP + 1회용 복구 코드.

불변식:
    INV-MF-01  TOTP 비밀키는 암호문으로만 저장된다. 평문은 등록 응답에 1회
    INV-MF-02  confirmed_at 이 None 인 등록은 로그인 요구 조건이 되지 않는다
    INV-RC-01  복구 코드 10개, 평문은 생성 응답에 1회. 저장은 해시
    INV-RC-02  used_at 이 설정된 코드는 재사용 불가

⭐ 2단계 등록(발급 → 첫 코드 검증)을 두는 이유:
   등록만 하고 확인하지 않은 상태에서 MFA 가 활성화되면, 인증 앱에 제대로
   등록되지 않은 채로 계정에 갇힙니다. 1인 운영 환경에서 실제로 일어납니다.

⭐ 복구 코드를 두는 이유:
   인증 앱을 잃으면 관리자 계정에 스스로 갇힙니다. MFA 를 넣으면서 복구
   경로를 만들지 않는 것이 그 사고의 원인입니다.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Final

from phc.shared import PasswordHash, UserId

__all__ = ["RECOVERY_CODE_COUNT", "MfaEnrollment", "MfaRecoveryCode", "RecoveryCodeId"]

RECOVERY_CODE_COUNT: Final = 10

#: 잔량이 이 이하이면 재발급을 안내합니다 (BR-MF-06).
RECOVERY_LOW_WATERMARK: Final = 3


@dataclass(frozen=True, slots=True, order=True)
class RecoveryCodeId:
    value: str

    @classmethod
    def generate(cls) -> RecoveryCodeId:
        return cls(uuid.uuid4().hex)

    def __str__(self) -> str:
        return self.value

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class MfaEnrollment:
    """TOTP 등록.

    ``secret_cipher`` 는 ``CipherPort`` 로 암호화된 바이트입니다.
    평문 비밀키를 담는 필드가 존재하지 않습니다 (INV-MF-01).
    """

    user_id: UserId
    secret_cipher: bytes
    enrolled_at: datetime
    confirmed_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        """INV-MF-02 — 확인 전에는 로그인 요구 조건이 아닙니다."""
        return self.confirmed_at is not None

    def confirm(self, *, now: datetime) -> MfaEnrollment:
        return replace(self, confirmed_at=now)

    def __redacted_repr__(self) -> str:
        return f"MfaEnrollment(user={self.user_id}, active={self.is_active})"


@dataclass(frozen=True, slots=True)
class MfaRecoveryCode:
    """1회용 복구 코드. 평문은 저장하지 않습니다 (INV-RC-01)."""

    id: RecoveryCodeId
    user_id: UserId
    code_hash: PasswordHash
    created_at: datetime
    used_at: datetime | None = None

    @property
    def is_available(self) -> bool:
        return self.used_at is None

    def consume(self, *, now: datetime) -> MfaRecoveryCode:
        """INV-RC-02 — 한 번 쓰면 끝입니다."""
        if self.used_at is not None:
            raise ValueError("이미 사용된 복구 코드입니다.")
        return replace(self, used_at=now)

    def __redacted_repr__(self) -> str:
        return f"MfaRecoveryCode(id={self.id}, used={not self.is_available})"
