"""인가 (S23). ⭐ 경계 B 의 세 번째 겹.

경계 B 는 세 겹입니다.

1. **의존 방향 차단** — ``identity`` 가 ``healthdata``·``advisory`` 를 모름
   (``pyproject.toml`` 계약 C2)
2. **API 표면에 우회 인자 부재** — ``OwnerScope`` 는 인증 주체로만 생성
   (``phc.shared.scope``)
3. **역할 무관 불변식** — ``require_owner`` 가 ``ctx.role`` 을 읽지 않음  ← 이 모듈

요구: FR-39 · FR-42 · NFR-46 · NFR-47 · US-42 · US-48 · RSK-10
"""

from __future__ import annotations

from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.ports.audit import AuditTrailPort
from phc.operations.services.metrics import MetricName, MetricsRegistry
from phc.shared import (
    AuthContext,
    AuthzError,
    ClockPort,
    OwnerScope,
    Role,
    UserId,
)

__all__ = ["OwnershipAuthorizer", "RoleAuthorizer"]


class RoleAuthorizer:
    """역할 인가 — **계정 도메인 리소스에만** 적용됩니다 (BR-AZ-04).

    관리자 역할이 부여하는 추가 권한의 범위가 여기서 끝납니다.
    건강 데이터에는 이 인가가 관여하지 않습니다.
    """

    def __init__(
        self,
        *,
        audit: AuditTrailPort,
        clock: ClockPort,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._audit = audit
        self._clock = clock
        self._metrics = metrics

    def require_admin(self, ctx: AuthContext, *, target_ref: str | None = None) -> None:
        """관리자가 아니면 거부하고 감사에 남긴다 (BR-AZ-05, BR-AZ-07).

        ⚠ 클라이언트 측 숨김에 의존하지 않습니다. 화면에서 버튼을 감췄더라도
        서버가 다시 확인합니다 (NFR-47).
        """
        if ctx.role is Role.ADMIN:
            return

        self._deny(ctx, target_ref=target_ref, judgement="role")
        raise AuthzError(detail=f"require_admin failed subject={ctx.subject_id}")

    def _deny(self, ctx: AuthContext, *, target_ref: str | None, judgement: str) -> None:
        if self._metrics is not None:
            self._metrics.increment(MetricName.AUTHZ_DENIED)
        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.AUTHZ_DENIED,
                outcome=AuditOutcome.DENIED,
                occurred_at=self._clock.now(),
                actor_user_id=ctx.subject_id,
                actor_role=ctx.role,
                target_ref=target_ref,
                detail={"judgement": judgement},
            )
        )


class OwnershipAuthorizer:
    """⭐ 소유권 인가 — **역할을 보지 않습니다**.

    이 클래스가 US-48("관리자도 타인의 건강 데이터를 볼 수 없다")의 코드
    수준 표현입니다.

    의존성으로 못박은 것:
        ``AccountRepository`` 를 **주입받지 않습니다.** 소유권 판정에 계정
        조회가 필요하지 않다는 사실을 생성자 시그니처로 표현합니다.
        역할을 확인하려면 계정을 읽어야 하는데, 읽을 수단이 없습니다.

    🔬 PBT 속성 3:
        모든 ``(AuthContext, resource_owner)`` 조합에 대해
        통과 ⇔ ``ctx.subject_id == resource_owner``. ``ctx.role`` 무관.
    """

    def __init__(
        self,
        *,
        audit: AuditTrailPort,
        clock: ClockPort,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._audit = audit
        self._clock = clock
        self._metrics = metrics

    def require_owner(
        self,
        ctx: AuthContext,
        resource_owner: UserId,
        *,
        target_ref: str | None = None,
    ) -> None:
        """소유자가 아니면 거부한다.

        ⭐ 이 메서드 본문에 ``ctx.role`` 이 등장하지 않습니다.
        관리자라는 이유로 통과하는 분기가 존재하지 않습니다 (BR-AZ-02).
        """
        if ctx.subject_id == resource_owner:
            return

        # 관리자의 시도도 동일하게 거부되고 동일하게 기록됩니다 (US-48).
        if self._metrics is not None:
            self._metrics.increment(MetricName.AUTHZ_DENIED)
        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.AUTHZ_DENIED,
                outcome=AuditOutcome.DENIED,
                occurred_at=self._clock.now(),
                actor_user_id=ctx.subject_id,
                actor_role=ctx.role,
                target_ref=target_ref or f"resource_owner:{resource_owner}",
                detail={"judgement": "ownership"},
            )
        )
        raise AuthzError(
            detail=f"require_owner failed subject={ctx.subject_id} owner={resource_owner}"
        )

    @staticmethod
    def scope_of(ctx: AuthContext) -> OwnerScope:
        """인증 주체의 소유 범위를 발급한다 — ``OwnerScope`` 의 유일 생성 경로.

        ``UserId`` 가 아니라 ``AuthContext`` 를 받으므로, 남의 식별자를 알아도
        그 사람의 스코프를 만들 수 없습니다 (BR-AZ-03).
        """
        return OwnerScope.for_subject(ctx)
