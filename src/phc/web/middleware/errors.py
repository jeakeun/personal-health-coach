"""오류 응답 (S32) — L-05 `GlobalErrorHandler` 의 웹 어댑터.

⭐ 배치가 보안 헤더 **바로 안쪽**입니다. 여기서 예외를 응답으로 바꾸므로,
   바깥의 `SecurityHeaderMiddleware` 가 오류 응답에도 헤더를 붙일 수 있습니다
   (NFR-1A-25).

⚠ 응답 본문에 스택 트레이스 · 내부 경로 · 프레임워크 버전을 담지 않습니다
   (NFR-1A-26, BR-ER-02). 사용자에게 주는 것은 안전한 문구와
   ``correlation_id`` 뿐이며, 상세는 로그에만 남습니다.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from phc.operations.services.logging import CorrelationIdProvider
from phc.operations.services.shutdown import SafeResponse
from phc.web.deps import get_deps
from phc.web.templating import render

__all__ = ["ErrorHandlingMiddleware", "error_response"]

_CallNext = Callable[[Request], Awaitable[Response]]


def error_response(request: Request, safe: SafeResponse) -> Response:
    """안전한 오류 응답을 만든다.

    브라우저 요청에는 HTML 을, 그 외에는 JSON 을 반환합니다. 판정은
    ``Accept`` 헤더로 합니다.
    """
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return render(
            request,
            "error.html",
            {
                "status_code": safe.status_code,
                "message": safe.message,
                "correlation_id": safe.correlation_id,
            },
            status_code=safe.status_code,
        )
    return JSONResponse(
        {
            "code": safe.code,
            "message": safe.message,
            "correlation_id": safe.correlation_id,
        },
        status_code=safe.status_code,
    )


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """미처리 예외를 안전한 응답으로 바꾼다."""

    async def dispatch(self, request: Request, call_next: _CallNext) -> Response:
        # 상관 ID 는 요청마다 새로 발급합니다. 로그와 오류 응답이 같은 값을
        # 인용해야 사용자 문의를 실제 로그로 이어 붙일 수 있습니다 (L-06).
        with CorrelationIdProvider.scope():
            try:
                return await call_next(request)
            except Exception as exc:  # 광범위 포착 사유: 여기가 마지막 방어선
                safe = get_deps(request).errors.handle(exc)
                return error_response(request, safe)
