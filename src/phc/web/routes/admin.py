"""관리자 라우트 (S34) — US-47 · US-48 · L-14 운영 상태 화면.

⭐ **이 파일에 건강 데이터로 가는 경로가 없습니다** (US-48, BR-AD-09).
   `AdminService` 가 반환하는 것은 `AccountSummary` 뿐이고, 그 타입에는
   건강 데이터 필드도 `password_hash` 도 존재하지 않습니다. 관리자 화면이
   표현할 수 있는 것의 상한이 그 타입입니다.

⚠ 화면에서 버튼을 감추는 것은 안내일 뿐입니다. 실제 거부는 서버가 합니다 —
   모든 관리자 동작이 `RoleAuthorizer.require_admin` 을 거칩니다 (BR-AZ-05).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse, RedirectResponse

from phc.operations.domain.audit import AuditEventType
from phc.operations.domain.job import JobState
from phc.operations.ports.audit import AuditFilter
from phc.shared import DomainError, Role, UserId
from phc.web.csrf import csrf_protect
from phc.web.deps import get_deps
from phc.web.flash import set_flash
from phc.web.forms import optional_text, required_text
from phc.web.routes.protected import require_ctx
from phc.web.templating import render

__all__ = ["router"]

router: Final = APIRouter(prefix="/admin")

#: 대시보드 조회 창 (nfr-design-patterns.md §5.4 — "최근 24시간").
_WINDOW: Final = timedelta(hours=24)

_ACTIONS: Final[dict[str, str]] = {
    "role": "역할 변경",
    "active": "활성 상태 변경",
    "reset": "비밀번호 재설정",
}


# ---------------------------------------------------------------------------
# 화면 6 — 관리자 콘솔 (US-47)
# ---------------------------------------------------------------------------
@router.get("")
async def console(request: Request) -> Response:
    ctx = require_ctx(request)
    deps = get_deps(request)
    accounts = deps.admin.list_accounts(ctx)
    return render(
        request,
        "admin_console.html",
        {"accounts": accounts, "active_admins": _active_admins(accounts)},
    )


@router.get("/confirm")
async def confirm(request: Request) -> Response:
    """파괴적 조작 확인 화면 (`ConfirmDialog`).

    ⭐ JavaScript 없이 동작하도록 **별도 페이지**로 만들었습니다. 상태를 바꾸지
       않는 GET 이므로 프리페치되어도 안전합니다 — 실제 변경은 이 화면의 POST 가
       합니다.
    """
    ctx = require_ctx(request)
    deps = get_deps(request)
    # 목록 조회 자체가 require_admin 을 거칩니다 — 확인 화면도 관리자만 봅니다.
    accounts = deps.admin.list_accounts(ctx)

    target = request.query_params.get("target", "")
    action = request.query_params.get("action", "")
    value = request.query_params.get("value", "")
    if action not in _ACTIONS:
        raise DomainError("unknown_action", "알 수 없는 요청입니다.")

    summary = next((a for a in accounts if str(a.id) == target), None)
    if summary is None:
        raise DomainError("account_not_found", "계정을 찾을 수 없습니다.")

    return render(
        request,
        "admin_confirm.html",
        {
            "account": summary,
            "action": action,
            "action_label": _ACTIONS[action],
            "value": value,
        },
    )


@router.post("/accounts/role", dependencies=[Depends(csrf_protect)])
async def set_role(request: Request) -> Response:
    ctx = require_ctx(request)
    form = await request.form()
    target = UserId(required_text(form, "target", label="대상 계정"))
    role = Role(required_text(form, "value", label="역할"))

    get_deps(request).admin.set_role(ctx, target, role)
    return _back("역할을 변경했습니다.")


@router.post("/accounts/active", dependencies=[Depends(csrf_protect)])
async def set_active(request: Request) -> Response:
    ctx = require_ctx(request)
    form = await request.form()
    target = UserId(required_text(form, "target", label="대상 계정"))
    active = optional_text(form, "value") == "true"

    get_deps(request).admin.set_active(ctx, target, active)
    return _back("활성 상태를 변경했습니다." if active else "계정을 비활성화했습니다.")


@router.post("/accounts/reset-password", dependencies=[Depends(csrf_protect)])
async def reset_password(request: Request) -> Response:
    """임시 비밀번호를 **1회만** 표시한다 (`OneTimeSecretPanel`, BR-AD-06).

    ⚠ 리다이렉트하지 않습니다. 리다이렉트하면 값을 어딘가에 실어 보내야 하고,
       그 순간 재조회 수단이 생깁니다. 감사에는 재설정 **사실만** 남고 값은
       남지 않습니다.
    """
    ctx = require_ctx(request)
    form = await request.form()
    deps = get_deps(request)
    target = UserId(required_text(form, "target", label="대상 계정"))

    result = deps.admin.reset_password(ctx, target)
    accounts = deps.admin.list_accounts(ctx)
    return render(
        request,
        "admin_console.html",
        {
            "accounts": accounts,
            "active_admins": _active_admins(accounts),
            "one_time_secret": result.temporary_password.reveal(),
            "one_time_target": str(result.target),
        },
    )


# ---------------------------------------------------------------------------
# L-14 운영 상태 화면 (ND5=A, RESILIENCY-05)
# ---------------------------------------------------------------------------
@router.get("/operations")
async def operations(request: Request) -> Response:
    """7개 영역을 렌더링한다.

    ⭐ **건강 데이터가 표시 항목에 없습니다.** 인가 거부 목록은 "누가 무엇에
       거부되었는가" 의 메타데이터만 보여 주고 대상 리소스의 내용은 보여 주지
       않습니다 (경계 B).
    """
    ctx = require_ctx(request)
    deps = get_deps(request)
    deps.roles.require_admin(ctx, target_ref="operations:dashboard")

    since = deps.clock.now() - _WINDOW
    counts = deps.jobs.count_by_state()
    backups = deps.backups.list_all()

    return render(
        request,
        "operations.html",
        {
            "health": deps.health.deep(),
            "auth_counts": {
                "success": deps.audit.count_since(AuditEventType.LOGIN_SUCCEEDED, since),
                "failure": deps.audit.count_since(AuditEventType.LOGIN_FAILED, since),
                "blocked": deps.audit.count_since(AuditEventType.LOGIN_BLOCKED, since),
            },
            "denials": deps.audit.query(
                AuditFilter(
                    event_types=frozenset({AuditEventType.AUTHZ_DENIED}),
                    since=since,
                    limit=20,
                )
            ),
            "jobs": {
                "pending": counts.get(JobState.PENDING.value, 0),
                "running": counts.get(JobState.RUNNING.value, 0),
                "failed": counts.get(JobState.FAILED.value, 0),
            },
            "last_backup_at": deps.backups.last_successful_at(),
            "backup_count": len(backups),
            "metrics": deps.metrics.snapshot(),
            "alerts": deps.alerts.list_open(limit=20),
        },
    )


@router.get("/health")
async def deep_health(request: Request) -> Response:
    """⚠ 인증 + 관리자 전용입니다 (SECURITY-09, BR-AZ §4.1)."""
    ctx = require_ctx(request)
    deps = get_deps(request)
    deps.roles.require_admin(ctx, target_ref="health:deep")

    status = deps.health.deep()
    return JSONResponse(
        {
            "state": status.state.value,
            "components": [
                {"name": c.name, "state": c.state.value, "detail": c.detail}
                for c in status.components
            ],
        }
    )


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    ctx = require_ctx(request)
    deps = get_deps(request)
    deps.roles.require_admin(ctx, target_ref="metrics")

    snapshot = deps.metrics.snapshot()
    return JSONResponse(
        {
            "counters": snapshot.counters,
            "gauges": snapshot.gauges,
            "histograms": {
                name: {"count": h.count, "p95": h.p95, "mean": h.mean}
                for name, h in snapshot.histograms.items()
            },
        }
    )


# ---------------------------------------------------------------------------
# 내부
# ---------------------------------------------------------------------------
def _active_admins(accounts: list[Any]) -> int:
    """마지막 관리자 안내용 개수. **거부 판정은 서버 서비스가 합니다** (BR-AD-03)."""
    return sum(1 for a in accounts if a.role is Role.ADMIN and a.is_active)


def _back(message: str) -> Response:
    response = RedirectResponse("/admin", status_code=303)
    set_flash(response, "success", message)
    return response
