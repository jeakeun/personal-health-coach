"""identity 도메인 — 계정 · 세션 · 스로틀 · MFA.

⚠ 이 패키지는 ``sqlalchemy`` · ``fastapi`` 를 import 하지 않습니다 (계약 C4).
⚠ ``identity`` 는 ``healthdata`` · ``advisory`` 를 import 하지 않습니다 (계약 C2, 경계 B).
"""

from __future__ import annotations

from phc.identity.domain.account import Account, AccountSummary
from phc.identity.domain.mfa import (
    RECOVERY_CODE_COUNT,
    MfaEnrollment,
    MfaRecoveryCode,
    RecoveryCodeId,
)
from phc.identity.domain.session import (
    DEFAULT_ABSOLUTE_LIFETIME,
    DEFAULT_IDLE_LIFETIME,
    Session,
    SessionInvalidReason,
    hash_token,
)
from phc.identity.domain.throttle import (
    DEFAULT_LOCKOUT_DURATION,
    DEFAULT_LOCKOUT_THRESHOLD,
    AttemptOutcome,
    LoginAttempt,
    ThrottleDecision,
    ThrottleKey,
    ThrottleState,
)

__all__ = [
    "DEFAULT_ABSOLUTE_LIFETIME",
    "DEFAULT_IDLE_LIFETIME",
    "DEFAULT_LOCKOUT_DURATION",
    "DEFAULT_LOCKOUT_THRESHOLD",
    "RECOVERY_CODE_COUNT",
    "Account",
    "AccountSummary",
    "AttemptOutcome",
    "LoginAttempt",
    "MfaEnrollment",
    "MfaRecoveryCode",
    "RecoveryCodeId",
    "Session",
    "SessionInvalidReason",
    "ThrottleDecision",
    "ThrottleKey",
    "ThrottleState",
    "hash_token",
]
