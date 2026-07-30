"""암호화 포트.

민감 필드(1A 에서는 TOTP 비밀키, 1B 이후 건강 데이터)의 암·복호화를 담당합니다
(NFR-01).

``CipherPurpose`` 로 용도를 구분하는 이유:
    같은 키로 모든 것을 암호화하면 한 용도의 암호문을 다른 용도에 끼워 넣는
    혼동 공격이 가능해집니다. 용도별로 키를 분리하여 암호문이 문맥을 벗어나
    재사용되지 못하게 합니다.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

__all__ = ["CipherPort", "CipherPurpose"]


class CipherPurpose(StrEnum):
    """암호화 용도. 용도마다 별개의 키를 사용합니다."""

    # 린트 예외 사유: 린터가 "MFA_SECRET" 이라는 이름 때문에 하드코딩된
    # 비밀번호로 오인합니다. 실제로는 키 용도를 구분하는 라벨이며 비밀값이 아닙니다.
    MFA_SECRET = "mfa_secret"  # noqa: S105
    BACKUP = "backup"
    HEALTH_FIELD = "health_field"  # Unit 1B 부터 사용


class CipherPort(Protocol):
    """민감 필드 암·복호화."""

    def encrypt(self, plain: bytes, purpose: CipherPurpose) -> bytes:
        """평문을 암호화한다.

        Raises:
            UndeterminedError: 키를 얻을 수 없는 경우. 호출자는 작업을
                실패시켜야 하며, 암호화 없이 저장해서는 안 됩니다.
        """
        ...

    def decrypt(self, cipher: bytes, purpose: CipherPurpose) -> bytes:
        """암호문을 복호화한다.

        Raises:
            UndeterminedError: 키를 얻을 수 없거나 복호화에 실패한 경우.
        """
        ...
