"""미들웨어 체인 (S32).

바깥 → 안쪽 순서입니다. 순서가 곧 방어 설계이므로
(`nfr-design-patterns.md` §4.1) 바꿀 때는 근거가 필요합니다.

    1. SecurityHeaderMiddleware   모든 응답에 헤더 (오류 응답 포함)
    2. ErrorHandlingMiddleware    예외 → 안전한 응답 (헤더보다 안쪽이어야 함)
    3. RateLimitMiddleware        비싼 연산(적응형 해시) 이전에 차단
    4. SessionMiddleware          세션 해석 → deny by default → 변경 강제
    5. CsrfCookieMiddleware       토큰 준비 (검증은 라우트 의존성)
"""

from __future__ import annotations

from phc.web.middleware.csrf import CsrfCookieMiddleware
from phc.web.middleware.errors import ErrorHandlingMiddleware
from phc.web.middleware.rate_limit import RateLimitMiddleware
from phc.web.middleware.security_headers import SecurityHeaderMiddleware
from phc.web.middleware.session import SessionMiddleware

__all__ = [
    "CsrfCookieMiddleware",
    "ErrorHandlingMiddleware",
    "RateLimitMiddleware",
    "SecurityHeaderMiddleware",
    "SessionMiddleware",
]
