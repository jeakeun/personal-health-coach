"""L-04 `CsrfGuard` 의 토큰 준비 (S32).

검증 자체는 라우트 의존성 `csrf_protect` 가, 누락 검사는 기동 시점
`assert_csrf_coverage` 가 담당합니다 (사유는 `phc.web.csrf` 문서 참조).
여기서는 **토큰이 항상 존재하도록** 보장합니다 — 폼을 렌더링하는 시점에
쿠키가 없으면 첫 제출이 반드시 실패하기 때문입니다.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from phc.web.csrf import generate_token
from phc.web.deps import COOKIE_CSRF, get_deps

__all__ = ["CsrfCookieMiddleware"]

_CallNext = Callable[[Request], Awaitable[Response]]


class CsrfCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: _CallNext) -> Response:
        token = request.cookies.get(COOKIE_CSRF)
        issued = token is None
        if token is None:
            token = generate_token()
        # 템플릿이 hidden input 에 넣을 값입니다.
        request.state.csrf_token = token

        response = await call_next(request)

        # 로그인 성공 시 라우트가 회전을 요청합니다 (고정 공격 방지).
        rotated = getattr(request.state, "csrf_rotate_to", None)
        if isinstance(rotated, str) and rotated:
            token, issued = rotated, True

        if issued:
            response.set_cookie(
                COOKIE_CSRF,
                token,
                httponly=True,
                samesite="lax",
                secure=get_deps(request).secure_cookies,
                path="/",
            )
        return response
