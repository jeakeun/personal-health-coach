"""공유 커널 — 전 도메인이 공유하는 타입 · 오류 · 포트.

이 모듈은 **어떤 도메인도 참조하지 않습니다** (의존 위계의 최하단).

여기 있는 타입들의 공통 성격은 "규칙을 문서가 아니라 타입으로 표현한다" 입니다.

    OwnerScope    남의 데이터를 조회하는 코드를 작성할 수 없게 함  (경계 B)
    SecretStr     평문 비밀이 로그·직렬화로 새지 않게 함
    PasswordHash  평문과 섞이지 않게 함
    Redactable    로그에 담아도 되는 값만 로그 함수에 전달되게 함
    SafetyVerdict "판정 불가" 를 "통과" 로 흘릴 수 없게 함
"""

from __future__ import annotations

from phc.shared.errors import (
    AuthzError,
    ConflictError,
    DomainError,
    PolicyViolationError,
    SafetyVerdict,
    StartupError,
    UndeterminedError,
    ValidationError,
)
from phc.shared.ports import CipherPort, CipherPurpose, ClockPort, SecretStorePort
from phc.shared.scope import OwnerScope
from phc.shared.types import (
    AuthContext,
    PasswordHash,
    Redactable,
    Role,
    SecretStr,
    SessionToken,
    SupportsRedactedRepr,
    UserId,
    Username,
)

__all__ = [
    "AuthContext",
    "AuthzError",
    "CipherPort",
    "CipherPurpose",
    "ClockPort",
    "ConflictError",
    "DomainError",
    "OwnerScope",
    "PasswordHash",
    "PolicyViolationError",
    "Redactable",
    "Role",
    "SafetyVerdict",
    "SecretStorePort",
    "SecretStr",
    "SessionToken",
    "StartupError",
    "SupportsRedactedRepr",
    "UndeterminedError",
    "UserId",
    "Username",
    "ValidationError",
]
