"""보호 라우트 (S34) — US-44(로그아웃) · US-49 · US-50.

`PUBLIC_ROUTES` 밖이므로 세션 미들웨어가 이미 인증을 요구했습니다
(BR-AZ-01). 여기 도달했다는 것은 인증된 주체가 있다는 뜻입니다.

⚠ 그래도 `ctx` 를 다시 확인합니다 — 미들웨어를 바꾸는 날 여기가 조용히
   무방비가 되지 않게 하기 위해서입니다.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import RedirectResponse

from phc.shared import AuthContext, AuthzError, DomainError, SessionToken
from phc.web.csrf import csrf_protect
from phc.web.deps import COOKIE_SESSION, current_ctx, get_deps
from phc.web.flash import set_flash
from phc.web.forms import optional_text, required_secret
from phc.web.templating import render

__all__ = ["require_ctx", "router"]

router: Final = APIRouter()


def require_ctx(request: Request) -> AuthContext:
    """⛔ 인증 컨텍스트가 없으면 거부한다 (두 번째 겹)."""
    ctx = current_ctx(request)
    if ctx is None:
        raise AuthzError(detail=f"보호 경로에 미인증 접근: {request.url.path}")
    return ctx


# ---------------------------------------------------------------------------
# 홈 — 1A 에서는 착지점만 있습니다 (내용은 1C·1D)
# ---------------------------------------------------------------------------
@router.get("/home")
async def home(request: Request) -> Response:
    ctx = require_ctx(request)
    account = get_deps(request).accounts.find_by_id(ctx.subject_id)
    return render(
        request,
        "home.html",
        {"display_name": account.display_name if account else str(ctx.subject_id)},
    )


# ---------------------------------------------------------------------------
# 화면 5 — 비밀번호 변경 (US-50 / US-46 강제)
# ---------------------------------------------------------------------------
@router.get("/account/password")
async def password_form(request: Request) -> Response:
    ctx = require_ctx(request)
    return render(request, "password_change.html", {"forced": ctx.must_change_password})


@router.post("/account/password", dependencies=[Depends(csrf_protect)])
async def password_submit(request: Request) -> Response:
    ctx = require_ctx(request)
    form = await request.form()
    deps = get_deps(request)

    try:
        current = required_secret(form, "current_password", label="현재 비밀번호")
        new = required_secret(form, "new_password", label="새 비밀번호")
        confirm = required_secret(form, "confirm_password", label="새 비밀번호 확인")
        if new != confirm:
            raise DomainError("password_mismatch", "새 비밀번호가 서로 다릅니다.")
        deps.auth.change_password(ctx, current, new)
    except DomainError as exc:
        return render(
            request,
            "password_change.html",
            {"forced": ctx.must_change_password, "form_error": exc.safe_message},
            status_code=400,
        )

    # ⭐ 자기 세션까지 전량 무효화되었으므로 (BR-PW-06) 쿠키도 지웁니다.
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_SESSION, path="/")
    set_flash(response, "success", "비밀번호가 변경되었습니다. 다시 로그인해 주세요.")
    return response


# ---------------------------------------------------------------------------
# 로그아웃 (FR-35)
# ---------------------------------------------------------------------------
@router.post("/logout", dependencies=[Depends(csrf_protect)])
async def logout(request: Request) -> Response:
    ctx = require_ctx(request)
    raw = request.cookies.get(COOKIE_SESSION)
    if raw:
        # 즉시 무효화입니다. 지연 삭제가 아닙니다 (BR-SE-06).
        get_deps(request).auth.logout(SessionToken(raw), ctx)

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_SESSION, path="/")
    set_flash(response, "success", "로그아웃되었습니다.")
    return response


# ---------------------------------------------------------------------------
# MFA 등록 (US-49)
# ---------------------------------------------------------------------------
@router.get("/account/mfa")
async def mfa_status(request: Request) -> Response:
    ctx = require_ctx(request)
    return render(
        request,
        "mfa_enroll.html",
        {"enabled": get_deps(request).mfa.is_required(ctx.subject_id)},
    )


@router.post("/account/mfa/begin", dependencies=[Depends(csrf_protect)])
async def mfa_begin(request: Request) -> Response:
    """1단계 — 비밀키를 **1회만** 표시합니다 (INV-MF-01).

    ⚠ 리다이렉트하지 않고 직접 렌더링합니다. 값이 쿠키·URL 에 실리면 남습니다.
    """
    ctx = require_ctx(request)
    deps = get_deps(request)
    account = deps.accounts.find_by_id(ctx.subject_id)
    challenge = deps.mfa.begin_enrollment(
        ctx.subject_id, account.display_name if account else str(ctx.subject_id)
    )
    return render(
        request,
        "mfa_enroll.html",
        {
            "enabled": False,
            "secret": challenge.secret.reveal(),
            "provisioning_uri": challenge.provisioning_uri,
        },
    )


@router.post("/account/mfa/confirm", dependencies=[Depends(csrf_protect)])
async def mfa_confirm(request: Request) -> Response:
    """2단계 — 확인해야 MFA 가 활성화됩니다 (INV-MF-02).

    확인 전에는 활성화되지 않으므로, 인증 앱에 제대로 등록되지 않은 채
    계정에 갇히는 일이 없습니다.
    """
    ctx = require_ctx(request)
    form = await request.form()
    deps = get_deps(request)

    try:
        bundle = deps.mfa.confirm_enrollment(ctx.subject_id, optional_text(form, "code"))
    except DomainError as exc:
        return render(
            request,
            "mfa_enroll.html",
            {"enabled": False, "form_error": exc.safe_message},
            status_code=400,
        )

    # 복구 코드도 1회 표시입니다 (INV-RC-01).
    return render(
        request,
        "mfa_enroll.html",
        {
            "enabled": True,
            "recovery_codes": [code.reveal() for code in bundle.codes],
        },
    )


@router.post("/account/mfa/disable", dependencies=[Depends(csrf_protect)])
async def mfa_disable(request: Request) -> Response:
    ctx = require_ctx(request)
    get_deps(request).mfa.disable(ctx.subject_id)
    response = RedirectResponse("/account/mfa", status_code=303)
    set_flash(response, "success", "다중 인증을 해제했습니다.")
    return response
