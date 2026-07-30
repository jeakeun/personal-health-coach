"""identity 애플리케이션 서비스 (D4=A — 명시적 오케스트레이션).

각 유스케이스마다 서비스 메서드가 컴포넌트 호출 순서를 직접 조율합니다.
이벤트 버스를 두지 않으므로 흐름이 코드에서 그대로 읽힙니다.
"""

from __future__ import annotations

from phc.identity.services.admin import AdminService, PasswordResetResult
from phc.identity.services.authentication import AuthService, LoginOutcome, SignUpResult
from phc.identity.services.authorization import OwnershipAuthorizer, RoleAuthorizer
from phc.identity.services.bootstrap import (
    BOOTSTRAP_USERNAME,
    AdminBootstrapper,
    BootstrapOutcome,
)
from phc.identity.services.mfa import (
    EnrollmentChallenge,
    MfaEnroller,
    MfaVerificationResult,
    RecoveryCodeBundle,
)
from phc.identity.services.passwords import MIN_PASSWORD_LENGTH, PasswordPolicy, PolicyResult
from phc.identity.services.sessions import IssuedSession, SessionManager
from phc.identity.services.throttling import LoginThrottle

__all__ = [
    "BOOTSTRAP_USERNAME",
    "MIN_PASSWORD_LENGTH",
    "AdminBootstrapper",
    "AdminService",
    "AuthService",
    "BootstrapOutcome",
    "EnrollmentChallenge",
    "IssuedSession",
    "LoginOutcome",
    "LoginThrottle",
    "MfaEnroller",
    "MfaVerificationResult",
    "OwnershipAuthorizer",
    "PasswordPolicy",
    "PasswordResetResult",
    "PolicyResult",
    "RecoveryCodeBundle",
    "RoleAuthorizer",
    "SessionManager",
    "SignUpResult",
]
