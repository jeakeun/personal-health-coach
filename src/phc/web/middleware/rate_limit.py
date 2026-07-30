"""L-02 `RateLimitMiddleware` — 체인 2번 (S32).

⭐ **인증보다 앞에 있어야 합니다.** Argon2id 는 의도적으로 비싼 연산입니다
   (64 MiB · t=3 · p=4). 레이트 리밋이 인증 뒤에 있으면 무차별 대입 시도가
   곧 메모리·CPU 소진 공격이 됩니다 — 로그인에 실패하더라도 자원은 이미
   소모된 뒤입니다.

한도 (NFR-1A-19): 로그인 분당 10회 / `client_key`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Final

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from phc.operations.services.shutdown import SafeResponse
from phc.web.deps import get_deps
from phc.web.middleware.errors import error_response
from phc.web.ratelimit import ClientKeyResolver, RateLimitRule

__all__ = ["DEFAULT_RULES", "RateLimitMiddleware"]

_CallNext = Callable[[Request], Awaitable[Response]]

#: 앞의 규칙이 우선합니다. 마지막 항목이 나머지 전부의 기본 한도입니다.
DEFAULT_RULES: Final[tuple[RateLimitRule, ...]] = (
    RateLimitRule("/login", limit=10, window=timedelta(minutes=1)),
    RateLimitRule("/mfa", limit=10, window=timedelta(minutes=1)),
    RateLimitRule("/signup", limit=10, window=timedelta(minutes=1)),
    # 나머지 경로는 넉넉하게 둡니다. 정상 사용을 막는 순간 사용자는 앱을
    # 신뢰하지 않게 되고, 그 비용이 로컬 앱에서는 방어 이득보다 큽니다.
    RateLimitRule("/", limit=600, window=timedelta(minutes=1)),
)

_TOO_MANY = SafeResponse(
    status_code=429,
    code="rate_limited",
    message="요청이 너무 잦습니다. 잠시 후 다시 시도해 주세요.",
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        rules: tuple[RateLimitRule, ...] = DEFAULT_RULES,
    ) -> None:
        super().__init__(app)
        self._rules = rules

    async def dispatch(self, request: Request, call_next: _CallNext) -> Response:
        deps = get_deps(request)
        client_key = ClientKeyResolver.resolve(
            request.client.host if request.client else None,
            request.headers.get("user-agent"),
        )
        # 로그인 라우트가 계정 스로틀 키로 씁니다. GET 에서도 채워 둡니다.
        request.state.client_key = client_key

        # 상태를 바꾸지 않는 조회까지 조이면 화면이 자주 깨집니다.
        # 비싼 경로는 전부 POST 입니다.
        if request.method == "GET":
            return await call_next(request)

        rule = self._rule_for(request.url.path)
        allowed = deps.rate_counter.hit(
            f"{rule.prefix}|{client_key}",
            now=deps.clock.now(),
            limit=rule.limit,
            window=rule.window,
        )
        if not allowed:
            return error_response(request, _TOO_MANY)

        return await call_next(request)

    def _rule_for(self, path: str) -> RateLimitRule:
        for rule in self._rules:
            if rule.prefix != "/" and path.startswith(rule.prefix):
                return rule
        return self._rules[-1]
