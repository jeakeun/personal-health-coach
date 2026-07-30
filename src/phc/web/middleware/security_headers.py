"""L-01 `SecurityHeaderMiddleware` — 체인 최외곽 (S32).

⭐ **오류 응답에도 붙어야 하므로 가장 바깥입니다.** 안쪽 어디에서 예외가
   나든, 응답이 나가는 길목은 여기 하나입니다. 순수 ASGI 로 구현해
   ``http.response.start`` 메시지에 직접 헤더를 넣습니다 — 응답 객체를
   거치지 않는 스트리밍 응답에도 동일하게 적용되게 하기 위해서입니다.

검증: NFR-1A-25 — 강제로 예외를 발생시킨 응답의 헤더를 검사합니다
(`tests/unit/test_web_middleware.py`).
"""

from __future__ import annotations

from typing import Final

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["SECURITY_HEADERS", "SecurityHeaderMiddleware"]

#: CSP — 인라인 스크립트·스타일을 허용하지 않습니다. 그래서 템플릿에
#: ``<style>`` · ``onclick=`` 이 없고 CSS·JS 가 ``/static/`` 파일로 나갑니다.
_CSP: Final = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

SECURITY_HEADERS: Final[dict[str, str]] = {
    "content-security-policy": _CSP,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    # 로컬 실행에는 해당 기능이 없지만, 기본값이 켜져 있는 브라우저를 위해
    # 명시적으로 끕니다.
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
    # 인증 화면과 관리자 화면이 캐시에 남지 않게 합니다.
    "cache-control": "no-store",
}

#: HSTS 는 로컬 HTTP 에서 의미가 없고, 켜면 브라우저가 이후 접속을 HTTPS 로
#: 강제해 앱이 열리지 않습니다. 클라우드 이전 시 플래그로 활성화합니다.
HSTS_HEADER: Final = ("strict-transport-security", "max-age=31536000; includeSubDomains")


class SecurityHeaderMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self._hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if self._hsts:
                    headers[HSTS_HEADER[0]] = HSTS_HEADER[1]
            await send(message)

        await self.app(scope, receive, send_with_headers)
