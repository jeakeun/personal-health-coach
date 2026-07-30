"""공개 라우트 (S33) — US-02 · US-43 · US-44 · US-45 · US-49.

`PUBLIC_ROUTES` 에 명시된 경로만 여기 있습니다. 목록에 없는 것을 추가하려면
`business-rules.md` §4.1 에 사유가 있어야 합니다 (BR-AZ-01).

⭐ 로그인 실패는 **원인을 구분하지 않습니다** — 계정 없음 · 비밀번호 틀림 ·
   비활성 · 잠금이 같은 문구, 같은 상태 코드로 돌아옵니다. 오류를 친절하게
   나누는 순간 계정 열거가 가능해집니다 (BR-TH-10/13).
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse, RedirectResponse

from phc.identity.services.sessions import IssuedSession
from phc.operations.services.logging import get_logger
from phc.shared import DomainError, SecretStr
from phc.web.csrf import csrf_protect, generate_token
from phc.web.deps import COOKIE_ACK, COOKIE_MFA, COOKIE_SESSION, current_ctx, get_deps
from phc.web.flash import set_flash
from phc.web.forms import next_path, optional_text, required_secret, required_text
from phc.web.templating import render

__all__ = ["router"]

router: Final = APIRouter()
_log = get_logger(__name__)

_GENERIC_LOGIN_FAILURE: Final = "사용자명 또는 비밀번호가 올바르지 않습니다."
_HOME = "/home"
# 린트 예외 사유: 라우트 경로이며 비밀번호 값이 아닙니다 (F-13 과 같은 부류).
_PASSWORD = "/account/password"  # noqa: S105


# ---------------------------------------------------------------------------
# 진입점
# ---------------------------------------------------------------------------
@router.get("/")
async def index(request: Request) -> Response:
    if request.cookies.get(COOKIE_ACK) != "1":
        return RedirectResponse("/onboarding", status_code=303)
    if current_ctx(request) is not None:
        return RedirectResponse(_HOME, status_code=303)
    return RedirectResponse("/login", status_code=303)


# ---------------------------------------------------------------------------
# 화면 1 — 최초 실행 안내 (US-02)
# ---------------------------------------------------------------------------
@router.get("/onboarding")
async def onboarding(request: Request) -> Response:
    return render(
        request,
        "onboarding.html",
        {"already_acknowledged": request.cookies.get(COOKIE_ACK) == "1"},
    )


@router.post("/onboarding/acknowledge", dependencies=[Depends(csrf_protect)])
async def acknowledge(request: Request) -> Response:
    """고지 확인을 기록한다.

    ⚠ **한계 기재 (F-26)**: 1A 의 DB 엔티티 10종에도 감사 이벤트 17종에도
       "고지 확인" 을 담을 자리가 없습니다. 감사 이벤트 목록은 닫힌 집합이라
       임의로 늘리지 않았습니다. 현재는 **구조화 로그**로 서버에 기록하고,
       재표시 억제는 쿠키로 합니다. 영속 저장이 필요한지는 1B 에서 판단합니다.
    """
    form = await request.form()
    if optional_text(form, "acknowledge") != "on":
        return render(
            request,
            "onboarding.html",
            {"already_acknowledged": False, "form_error": "고지를 확인해 주세요."},
            status_code=400,
        )

    _log.info("onboarding.acknowledged")
    response = RedirectResponse("/signup", status_code=303)
    response.set_cookie(
        COOKIE_ACK,
        "1",
        httponly=True,
        samesite="lax",
        secure=get_deps(request).secure_cookies,
        max_age=60 * 60 * 24 * 365,
        path="/",
    )
    return response


# ---------------------------------------------------------------------------
# 화면 2 — 회원가입 (US-43)
# ---------------------------------------------------------------------------
@router.get("/signup")
async def signup_form(request: Request) -> Response:
    return render(request, "signup.html", {})


@router.post("/signup", dependencies=[Depends(csrf_protect)])
async def signup_submit(request: Request) -> Response:
    form = await request.form()
    deps = get_deps(request)

    try:
        username = required_text(form, "username", label="사용자명")
        password = required_secret(form, "password", label="비밀번호")
        deps.auth.sign_up(username, password)
    except DomainError as exc:
        # ⚠ 중복 사용자명도 일반화된 문구로 돌아옵니다 (BR-SU-03).
        return render(
            request,
            "signup.html",
            {"form_error": exc.safe_message, "username": optional_text(form, "username")},
            status_code=400,
        )

    response = RedirectResponse("/login", status_code=303)
    set_flash(response, "success", "가입이 완료되었습니다. 로그인해 주세요.")
    return response


# ---------------------------------------------------------------------------
# 화면 3 — 로그인 (US-44, US-45)
# ---------------------------------------------------------------------------
@router.get("/login")
async def login_form(request: Request) -> Response:
    return render(request, "login.html", {"next": next_path(request.query_params.get("next"))})


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login_submit(request: Request) -> Response:
    form = await request.form()
    deps = get_deps(request)
    target = next_path(optional_text(form, "next") or None)

    try:
        username = required_text(form, "username", label="사용자명")
        password = required_secret(form, "password", label="비밀번호")
    except DomainError:
        # 입력 누락도 같은 문구입니다 — 어떤 필드가 문제인지 알려 주면
        # 사용자명 존재 여부를 탐색하는 실마리가 됩니다.
        return _login_failed(request, target)

    outcome = deps.auth.login(username, password, client_key=_client_key(request))

    if outcome.mfa_required:
        return _to_mfa(request, username=username, password=password)

    if not outcome.succeeded or outcome.session is None:
        return _login_failed(request, target)

    return _establish_session(
        request, outcome.session, target=target, forced=outcome.must_change_password
    )


# ---------------------------------------------------------------------------
# 화면 4 — MFA 코드 입력 (US-49)
# ---------------------------------------------------------------------------
@router.get("/mfa")
async def mfa_form(request: Request) -> Response:
    deps = get_deps(request)
    if not deps.pending_mfa.peek(request.cookies.get(COOKIE_MFA), now=deps.clock.now()):
        return RedirectResponse("/login", status_code=303)
    return render(request, "mfa.html", {"mode": request.query_params.get("mode", "totp")})


@router.post("/mfa", dependencies=[Depends(csrf_protect)])
async def mfa_submit(request: Request) -> Response:
    form = await request.form()
    deps = get_deps(request)

    # ⭐ 대기 표식은 1회용입니다. 실패하면 아래에서 새로 발급합니다 —
    #    토큰 하나로 코드를 무제한 시도할 수 없게 하기 위함입니다.
    pending = deps.pending_mfa.take(request.cookies.get(COOKIE_MFA), now=deps.clock.now())
    if pending is None:
        response = RedirectResponse("/login", status_code=303)
        set_flash(response, "error", "인증 시간이 만료되었습니다. 다시 로그인해 주세요.")
        response.delete_cookie(COOKIE_MFA, path="/")
        return response

    code = optional_text(form, "code")
    outcome = deps.auth.login(
        pending.display_name,
        pending.password,
        client_key=pending.client_key,
        mfa_code=code,
    )

    if not outcome.succeeded or outcome.session is None:
        # ⚠ TOTP 실패와 복구 코드 실패를 구분하지 않습니다.
        #    재시도 횟수는 계정 스로틀이 제한합니다 (BR-TH).
        return _to_mfa(
            request,
            username=pending.display_name,
            password=pending.password,
            error=_GENERIC_LOGIN_FAILURE,
            mode=optional_text(form, "mode") or "totp",
        )

    return _establish_session(
        request, outcome.session, target=None, forced=outcome.must_change_password
    )


# ---------------------------------------------------------------------------
# 얕은 헬스체크 — 공개 (BR-AZ §4.1)
# ---------------------------------------------------------------------------
@router.get("/healthz")
async def healthz(request: Request) -> Response:
    """⚠ 프로세스 생존만 반환합니다.

    DB·워커·키저장소 상태는 **깊은 헬스체크**(인증 필요)에 있습니다. 의존 구성이
    드러나면 공격 표면 파악에 쓰입니다 (SECURITY-09).
    """
    status = get_deps(request).health.shallow()
    return JSONResponse({"state": status.state.value})


# ---------------------------------------------------------------------------
# 내부
# ---------------------------------------------------------------------------
def _client_key(request: Request) -> str:
    key = getattr(request.state, "client_key", None)
    return key if isinstance(key, str) else "unknown"


def _login_failed(request: Request, target: str | None) -> Response:
    """⭐ 실패 응답은 하나뿐입니다 — 본문·상태 코드가 원인과 무관합니다."""
    return render(
        request,
        "login.html",
        {"form_error": _GENERIC_LOGIN_FAILURE, "next": target},
        status_code=200,
    )


def _to_mfa(
    request: Request,
    *,
    username: str,
    password: SecretStr,
    error: str | None = None,
    mode: str = "totp",
) -> Response:
    deps = get_deps(request)
    token = deps.pending_mfa.put(
        display_name=username,
        password=password,
        client_key=_client_key(request),
        now=deps.clock.now(),
    )
    response = (
        render(request, "mfa.html", {"mode": mode, "form_error": error})
        if error
        else RedirectResponse("/mfa", status_code=303)
    )
    response.set_cookie(
        COOKIE_MFA,
        token,
        httponly=True,
        samesite="lax",
        secure=deps.secure_cookies,
        path="/",
    )
    return response


def _establish_session(
    request: Request,
    issued: IssuedSession,
    *,
    target: str | None,
    forced: bool,
) -> Response:
    deps = get_deps(request)

    destination = _PASSWORD if forced else (target or _HOME)
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        COOKIE_SESSION,
        issued.token.value,
        httponly=True,
        samesite="lax",
        secure=deps.secure_cookies,
        path="/",
    )
    # 대기 표식은 더 이상 필요 없습니다.
    response.delete_cookie(COOKIE_MFA, path="/")
    # ⭐ 인증 상태가 바뀌었으므로 CSRF 토큰도 회전시킵니다 (고정 공격 방지).
    request.state.csrf_rotate_to = generate_token()

    if forced:
        set_flash(response, "error", "임시 비밀번호로 로그인했습니다. 비밀번호를 변경해 주세요.")
    return response
