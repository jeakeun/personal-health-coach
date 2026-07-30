"""CSRF 방어 (S32) — L-04 `CsrfGuard`.

동기화 토큰 패턴입니다. 토큰을 **HttpOnly 쿠키**에 두고 폼에 같은 값을 렌더링한
뒤 제출값과 대조합니다. 쿠키 `SameSite=Lax` 와 이중 방어입니다.

⚠ **설계와 달라진 두 지점과 그 이유** (발견 사항 F-25)

    1. 논리 설계는 "세션에 토큰 저장" 이라고 적었으나, **회원가입·로그인 폼에는
       세션이 없습니다.** 그럼에도 예외를 두지 않기로 했으므로(L-04 "예외: 없음")
       세션과 무관하게 존재할 수 있는 저장소가 필요합니다 → 쿠키.
       로그인 성공 시 토큰을 **회전**시켜 고정 공격을 막습니다.

    2. 논리 설계는 "미들웨어" 라고 적었으나 **폼 본문은 ASGI 스트림에서 한 번만
       읽을 수 있습니다.** 미들웨어가 읽으면 라우트가 다시 읽지 못합니다.
       그래서 검증은 **라우트 의존성**(`csrf_protect`)이 수행하고,
       누락은 **기동 시점**에 `assert_csrf_coverage` 가 잡습니다.

       ⭐ 요청 시점 사후 검사가 아니라 기동 시점 검사인 이유: 사후 검사는 이미
          부작용이 실행된 뒤라 거부해도 소용이 없습니다. 기동 시 막으면 의존성을
          빠뜨린 라우트가 있는 앱은 **아예 뜨지 않습니다** (NFR-09 fail closed).
"""

from __future__ import annotations

import secrets
from typing import Any, Final

from fastapi import Request
from starlette.routing import BaseRoute

from phc.shared import DomainError, StartupError

__all__ = [
    "CSRF_FIELD",
    "SAFE_METHODS",
    "CsrfError",
    "assert_csrf_coverage",
    "csrf_protect",
    "generate_token",
    "verify_form_token",
]

#: 폼 필드 이름. 템플릿의 hidden input 과 같아야 합니다.
CSRF_FIELD: Final = "csrf_token"

#: 상태를 바꾸지 않는 메서드. GET 으로 상태를 바꾸는 경로를 두지 않으므로
#: 이 목록이 곧 "검증 불필요" 목록입니다.
SAFE_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})

_TOKEN_BYTES: Final = 32


class CsrfError(DomainError):
    """⛔ CSRF 토큰 불일치 — 요청을 수행하지 않습니다."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            "csrf_failed",
            "요청이 만료되었거나 올바르지 않습니다. 화면을 새로 고친 뒤 다시 시도해 주세요.",
            detail=detail,
        )


def generate_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def verify_form_token(request: Request, submitted: str | None) -> None:
    """제출된 토큰을 쿠키의 값과 대조한다.

    Raises:
        CsrfError: 쿠키가 없거나 값이 다른 경우.
    """
    from phc.web.deps import COOKIE_CSRF  # 순환 import 방지

    expected = request.cookies.get(COOKIE_CSRF)
    if not expected or not submitted:
        raise CsrfError("토큰 부재")
    if not secrets.compare_digest(expected, submitted):
        raise CsrfError("토큰 불일치")


async def csrf_protect(request: Request) -> None:
    """상태 변경 라우트가 반드시 선언해야 하는 의존성.

    ``request.form()`` 은 Starlette 가 요청 객체에 캐시하므로, 라우트 본문이
    같은 폼을 다시 읽어도 문제가 없습니다.
    """
    form = await request.form()
    submitted = form.get(CSRF_FIELD)
    verify_form_token(request, submitted if isinstance(submitted, str) else None)


def assert_csrf_coverage(routes: list[BaseRoute]) -> None:
    """⛔ 상태 변경 라우트가 전부 `csrf_protect` 를 선언했는지 확인한다.

    하나라도 빠지면 앱을 기동하지 않습니다. "새 라우트를 추가하면서 잊어버렸다"
    가 조용한 취약점이 되지 않게 하는 장치입니다.

    Raises:
        StartupError: 보호되지 않은 상태 변경 라우트가 있는 경우.
    """
    unprotected: list[str] = []

    for route in routes:
        methods = getattr(route, "methods", None) or set()
        unsafe = {method for method in methods if method not in SAFE_METHODS}
        if not unsafe:
            continue
        if not _declares_guard(route):
            path = getattr(route, "path", "?")
            unprotected.append(f"{sorted(unsafe)} {path}")

    if unprotected:
        raise StartupError(
            "CSRF 보호가 선언되지 않은 상태 변경 경로가 있습니다.",
            detail="; ".join(unprotected),
        )


def _declares_guard(route: BaseRoute) -> bool:
    dependant: Any = getattr(route, "dependant", None)
    if dependant is None:
        return False
    return any(dependency.call is csrf_protect for dependency in dependant.dependencies)
