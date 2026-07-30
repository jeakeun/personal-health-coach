"""요청 처리에 필요한 의존성과 상수 (S32).

조립은 S37(조립 루트)이 합니다. 여기서는 **무엇이 필요한지**만 선언합니다.

⭐ ``WebDeps`` 에 **건강 데이터 리포지토리가 없습니다.** 1B 이후에도
   표현 계층이 소유자 범위 없이 건강 데이터를 만지는 경로가 생기지 않도록,
   접근은 항상 서비스와 ``OwnerScope`` 를 거칩니다 (경계 B).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from fastapi import Request

from phc.identity.ports.repositories import AccountRepositoryPort
from phc.identity.services.admin import AdminService
from phc.identity.services.authentication import AuthService
from phc.identity.services.authorization import RoleAuthorizer
from phc.identity.services.mfa import MfaEnroller
from phc.identity.services.sessions import SessionManager
from phc.operations.ports.alert_store import AlertStorePort
from phc.operations.ports.audit import AuditTrailPort
from phc.operations.ports.backup_store import BackupStorePort
from phc.operations.ports.job_queue import JobQueuePort
from phc.operations.services.health import HealthProbe
from phc.operations.services.metrics import MetricsRegistry
from phc.operations.services.shutdown import GlobalErrorHandler
from phc.shared import AuthContext, ClockPort

if TYPE_CHECKING:  # 순환 import 방지 — 런타임에는 필요하지 않습니다.
    from phc.web.pending import PendingMfaStore
    from phc.web.ratelimit import InMemoryRateCounter

__all__ = [
    "ALLOWED_WHEN_MUST_CHANGE",
    "COOKIE_ACK",
    "COOKIE_CSRF",
    "COOKIE_FLASH",
    "COOKIE_MFA",
    "COOKIE_SESSION",
    "PUBLIC_ROUTES",
    "WebDeps",
    "current_ctx",
    "get_deps",
    "is_public",
]

# ---------------------------------------------------------------------------
# 쿠키 이름
# ---------------------------------------------------------------------------
#: 세션 토큰. HttpOnly · SameSite=Lax (BR-SE, D6=A).
COOKIE_SESSION: Final = "phc_session"
#: CSRF 토큰 (L-04).
COOKIE_CSRF: Final = "phc_csrf"
#: 1차 인증 통과 후 MFA 입력까지의 임시 표식.
COOKIE_MFA: Final = "phc_mfa"
#: 플래시 메시지 — 리다이렉트 후 1회 표시하고 삭제합니다.
COOKIE_FLASH: Final = "phc_flash"
#: 최초 실행 안내 확인 표식 (US-02).
COOKIE_ACK: Final = "phc_ack"


# ---------------------------------------------------------------------------
# 공개 경로 (BR-AZ-01 · business-rules.md §4.1)
#
# ⭐ **이 목록에 없으면 전부 인증이 필요합니다.** 목록을 늘리는 것이 곧
#    공격 표면을 늘리는 것이므로, 추가할 때는 §4.1 에 사유가 있어야 합니다.
#
# ⚠ 여기 **없는** 것을 명시해 둡니다 — 깊은 헬스체크·메트릭은 의존 구성을
#    드러내므로 인증이 필요합니다 (SECURITY-09).
# ---------------------------------------------------------------------------
PUBLIC_ROUTES: Final[frozenset[str]] = frozenset(
    {
        "/",
        "/onboarding",
        "/onboarding/acknowledge",
        "/signup",
        "/login",
        "/mfa",  # 준공개 — 1차 인증 통과 표식이 있어야 실제로 열립니다
        "/healthz",  # 얕은 헬스체크만
    }
)

#: 정적 자산 접두사. 민감정보를 담지 않습니다.
_PUBLIC_PREFIX: Final = "/static/"

#: ⭐ ``must_change_password`` 상태에서 유일하게 허용되는 경로 (BR-AZ-06).
ALLOWED_WHEN_MUST_CHANGE: Final[frozenset[str]] = frozenset(
    {"/account/password", "/logout", "/healthz"}
)


def is_public(path: str) -> bool:
    return path in PUBLIC_ROUTES or path.startswith(_PUBLIC_PREFIX)


# ---------------------------------------------------------------------------
# 의존성 묶음
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class WebDeps:
    """표현 계층이 쓰는 것 전부. 조립 루트(S37)가 채웁니다."""

    auth: AuthService
    admin: AdminService
    sessions: SessionManager
    mfa: MfaEnroller
    roles: RoleAuthorizer
    accounts: AccountRepositoryPort
    health: HealthProbe
    metrics: MetricsRegistry
    audit: AuditTrailPort
    alerts: AlertStorePort
    jobs: JobQueuePort
    backups: BackupStorePort
    clock: ClockPort
    errors: GlobalErrorHandler
    pending_mfa: PendingMfaStore
    rate_counter: InMemoryRateCounter
    #: 클라우드 이전 시 ``True`` — 로컬 HTTP 에서는 쿠키가 전송되지 않게 됩니다.
    secure_cookies: bool = False


def get_deps(request: Request) -> WebDeps:
    deps = request.app.state.deps
    if not isinstance(deps, WebDeps):  # pragma: no cover - 조립 오류 방어
        raise RuntimeError("WebDeps 가 앱에 주입되지 않았습니다.")
    return deps


def current_ctx(request: Request) -> AuthContext | None:
    """세션 미들웨어가 주입한 인증 컨텍스트. 미인증이면 ``None``."""
    ctx = getattr(request.state, "ctx", None)
    return ctx if isinstance(ctx, AuthContext) else None
