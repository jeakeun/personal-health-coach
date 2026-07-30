"""Jinja2 렌더링 (S35).

서버 렌더링 다중 페이지입니다 (F10=A). 클라이언트 라우팅도, 전역 상태
저장소도 두지 않습니다 — 인증 상태를 클라이언트에 복제하면 "클라이언트가
이미 아는데 서버에서 또 확인할 필요가 있나" 라는 경로가 생기고, NFR-46/47 이
정확히 그것을 금지합니다.

⭐ 자동 이스케이프가 켜져 있습니다. 사용자 입력(사용자명·표시 이름)이 그대로
   화면에 나가는 지점이 있으므로 끄면 즉시 XSS 가 됩니다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse

from phc.web.csrf import CSRF_FIELD
from phc.web.deps import COOKIE_CSRF, current_ctx
from phc.web.flash import clear, read

__all__ = ["TEMPLATES_DIR", "render", "templates"]

TEMPLATES_DIR: Final = Path(__file__).parent / "templates"

templates: Final = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True
templates.env.trim_blocks = True
templates.env.lstrip_blocks = True


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
) -> HTMLResponse:
    """템플릿을 렌더링하고 공통 컨텍스트를 채운다.

    공통으로 넣는 것:
        ``ctx``          인증 컨텍스트 (미인증이면 ``None``)
        ``csrf_token``   폼의 hidden input 에 들어갈 값
        ``csrf_field``   그 input 의 name
        ``flash``        1회 표시 메시지 (읽으면서 쿠키 삭제)
    """
    ctx = current_ctx(request)
    flash = read(request)

    response = templates.TemplateResponse(
        request=request,
        name=name,
        context={
            **(context or {}),
            "ctx": ctx,
            "csrf_token": _csrf_token(request),
            "csrf_field": CSRF_FIELD,
            "flash": flash,
            # 강제 변경 상태에서는 레이아웃이 링크를 감춥니다. 서버가 이미
            # BR-AZ-06 으로 차단하므로 화면 처리는 보조 수단입니다.
            "is_forced": bool(ctx and ctx.must_change_password),
        },
        status_code=status_code,
    )
    if flash is not None:
        clear(response)
    return response


def _csrf_token(request: Request) -> str:
    """미들웨어가 준비한 토큰. 없으면 쿠키 값을 그대로 씁니다."""
    token = getattr(request.state, "csrf_token", None)
    if isinstance(token, str) and token:
        return token
    return request.cookies.get(COOKIE_CSRF, "")
