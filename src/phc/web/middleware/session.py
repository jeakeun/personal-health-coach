"""L-03 `SessionMiddleware` — 체인 3~5번 (S32).

세 가지를 순서대로 합니다.

    3. 세션 해석        쿠키 → `SessionManager.resolve` → `AuthContext`
    4. deny by default  `PUBLIC_ROUTES` 밖이면 인증 필수 (BR-AZ-01)
    5. 변경 강제 검사    `must_change_password` 이면 경로 제한 (BR-AZ-06)

⭐ **Starlette 의 `SessionMiddleware` 를 쓰지 않습니다.** 그것은 서명된 쿠키에
   상태를 담는 방식이라 클라이언트가 세션을 보관하게 됩니다. 그러면 FR-35
   ("로그아웃 시 즉시 무효화")가 성립하지 않습니다 — 서버가 지울 것이 없기
   때문입니다. D6=A 는 서버 측 세션입니다.

⛔ 세션 조회가 **실패**하면 통과시키지 않습니다. `SessionManager.resolve` 가
   `UndeterminedError` 를 던지고, 오류 미들웨어가 503 으로 바꿉니다
   (BR-SE-10, NFR-09 fail closed). "조회를 못 했으니 일단 통과" 가 없습니다.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

from phc.shared import AuthContext, SessionToken
from phc.web.deps import (
    ALLOWED_WHEN_MUST_CHANGE,
    COOKIE_SESSION,
    get_deps,
    is_public,
)
from phc.web.flash import set_flash

__all__ = ["SessionMiddleware"]

_CallNext = Callable[[Request], Awaitable[Response]]

# 린트 예외 사유: 라우트 경로이며 비밀번호 값이 아닙니다 (F-13 과 같은 부류).
_PASSWORD_PATH = "/account/password"  # noqa: S105
_LOGIN_PATH = "/login"


class SessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: _CallNext) -> Response:
        path = request.url.path

        ctx, stale_cookie = self._resolve(request)
        request.state.ctx = ctx

        # --- 4. deny by default (BR-AZ-01) --------------------------------
        if ctx is None and not is_public(path):
            response = self._to_login(request)
            if stale_cookie:
                # 만료 사유를 안내합니다. 어느 계정이었는지는 말하지 않습니다.
                set_flash(response, "error", "세션이 만료되었습니다. 다시 로그인해 주세요.")
                response.delete_cookie(COOKIE_SESSION, path="/")
            return response

        # --- 5. 변경 강제 검사 (BR-AZ-06) ---------------------------------
        # ⭐ 화면에서 링크를 감추는 것과 별개로, 주소를 직접 입력해도 막힙니다.
        if (
            ctx is not None
            and ctx.must_change_password
            and path not in ALLOWED_WHEN_MUST_CHANGE
            and not is_public(path)
        ):
            return RedirectResponse(_PASSWORD_PATH, status_code=303)

        return await call_next(request)

    # ------------------------------------------------------------------ 내부
    @staticmethod
    def _resolve(request: Request) -> tuple[AuthContext | None, bool]:
        """쿠키에서 인증 컨텍스트를 만든다.

        Returns:
            ``(컨텍스트, 쿠키는 있었으나 무효였는가)``
        """
        raw = request.cookies.get(COOKIE_SESSION)
        if not raw:
            return None, False

        deps = get_deps(request)
        session = deps.sessions.resolve(SessionToken(raw))
        if session is None:
            return None, True

        account = deps.accounts.find_by_id(session.user_id)
        if account is None or not account.can_sign_in:
            # 계정이 사라졌거나 비활성화되었으면 세션도 끝입니다 (BR-AD-05).
            deps.sessions.revoke(SessionToken(raw))
            return None, True

        return deps.sessions.to_context(session, account), False

    @staticmethod
    def _to_login(request: Request) -> RedirectResponse:
        """로그인 화면으로 보낸다. **경로만** 보존합니다.

        폼 입력값은 보존하지 않습니다 — 만료된 세션의 입력을 서버가 들고 있으면
        그 자체가 보관 대상이 됩니다 (`frontend-components.md` §5.3).
        """
        target = request.url.path
        if request.method == "GET" and target not in {"/", _LOGIN_PATH}:
            return RedirectResponse(f"{_LOGIN_PATH}?next={target}", status_code=303)
        return RedirectResponse(_LOGIN_PATH, status_code=303)
