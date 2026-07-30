"""identity 포트.

⚠ 계정 도메인 리포지토리는 ``OwnerScope`` 를 받지 **않습니다**.
   관리자 기능(계정 목록·역할 변경)이 성립해야 하기 때문입니다.

   반대로 1B 이후 추가되는 **모든 건강 데이터 리포지토리는 ``OwnerScope`` 를
   필수 인자로 받습니다.** 이 비대칭이 경계 B 의 형태입니다.
"""

from __future__ import annotations

from phc.identity.ports.breach_list import BreachedPasswordListPort
from phc.identity.ports.password import PasswordHasherPort
from phc.identity.ports.repositories import (
    AccountRepositoryPort,
    MfaRepositoryPort,
    SessionRepositoryPort,
    ThrottleRepositoryPort,
)
from phc.identity.ports.totp import TotpPort

__all__ = [
    "AccountRepositoryPort",
    "BreachedPasswordListPort",
    "MfaRepositoryPort",
    "PasswordHasherPort",
    "SessionRepositoryPort",
    "ThrottleRepositoryPort",
    "TotpPort",
]
