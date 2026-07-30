"""🔬 PBT 속성 3 — 소유자 전용 반환, 역할 무관 (PBT-03). ⭐ 경계 B

**진술**: 임의의 ``(AuthContext ctx, UserId resource_owner)`` 조합에 대해
``require_owner(ctx, resource_owner)`` 가 통과할 필요충분조건은
``ctx.subject_id == resource_owner`` 이다. **``ctx.role`` 의 값은 결과에
영향을 주지 않는다.**

반례가 잡는 것:
    관리자 우회 분기 · IDOR

근거: US-42 · US-48 · AC-19 · AC-20 · RSK-10

⭐ 확장 규정 (unit-of-work-story-map.md §5):
    1B 이후 각 유닛은 **자기 리포지토리를 이 속성의 생성기에 등록**합니다.
    "임의 scope 로 조회 시 owner 가 다른 레코드는 반환되지 않는다" 를
    리포지토리마다 검증하기 위함입니다. 1A 에는 건강 데이터 리포지토리가
    없으므로 인가 판정 자체와 ``OwnerScope`` 생성 경로를 검증합니다.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phc.identity.services.authorization import OwnershipAuthorizer
from phc.operations.adapters.in_memory import InMemoryAuditTrail
from phc.operations.domain.audit import AuditEventType
from phc.operations.ports.audit import AuditFilter
from phc.shared import AuthContext, AuthzError, OwnerScope, Role, UserId
from phc.shared.ports.clock import FixedClock
from tests.conftest import NOW

pytestmark = pytest.mark.property

_IDS = st.sampled_from(["alice", "bob", "carol", "admin-1", "u-42"])
_ROLES = st.sampled_from([Role.USER, Role.ADMIN])


def _authorizer() -> tuple[OwnershipAuthorizer, InMemoryAuditTrail]:
    audit = InMemoryAuditTrail()
    return OwnershipAuthorizer(audit=audit, clock=FixedClock(NOW)), audit


@given(subject=_IDS, role=_ROLES, owner=_IDS)
@settings(max_examples=300)
def test_통과_여부는_식별자_일치와_정확히_같다(subject: str, role: Role, owner: str) -> None:
    """(a) 통과 ⇔ subject_id == resource_owner."""
    authorizer, _ = _authorizer()
    ctx = AuthContext(UserId(subject), role)

    if subject == owner:
        authorizer.require_owner(ctx, UserId(owner))  # 예외가 없어야 한다
    else:
        with pytest.raises(AuthzError):
            authorizer.require_owner(ctx, UserId(owner))


@given(subject=_IDS, owner=_IDS)
@settings(max_examples=300)
def test_역할을_바꿔도_결과가_같다(subject: str, owner: str) -> None:
    """(b) ⭐ 같은 식별자 쌍이면 USER 든 ADMIN 이든 동일한 결과."""
    authorizer, _ = _authorizer()

    def outcome(role: Role) -> bool:
        try:
            authorizer.require_owner(AuthContext(UserId(subject), role), UserId(owner))
        except AuthzError:
            return False
        return True

    assert outcome(Role.USER) == outcome(Role.ADMIN)


@given(subject=_IDS, role=_ROLES, owner=_IDS)
@settings(max_examples=200)
def test_거부는_예외없이_감사에_남는다(subject: str, role: Role, owner: str) -> None:
    """(c) US-48 인수 기준 — '거부가 감사 로그에 기록된다'."""
    authorizer, audit = _authorizer()
    ctx = AuthContext(UserId(subject), role)

    denied = False
    try:
        authorizer.require_owner(ctx, UserId(owner))
    except AuthzError:
        denied = True

    entries = audit.query(
        AuditFilter(event_types=frozenset({AuditEventType.AUTHZ_DENIED}), limit=10)
    )
    assert len(entries) == (1 if denied else 0)


@given(subject=_IDS, role=_ROLES)
@settings(max_examples=200)
def test_스코프는_언제나_자기_자신을_가리킨다(subject: str, role: Role) -> None:
    """(d) ``OwnerScope`` 생성 경로도 역할을 보지 않는다."""
    ctx = AuthContext(UserId(subject), role)
    scope = OwnershipAuthorizer.scope_of(ctx)

    assert scope.owner_id == ctx.subject_id
    assert scope == OwnerScope.for_subject(AuthContext(UserId(subject), Role.ADMIN))
    assert scope == OwnerScope.for_subject(AuthContext(UserId(subject), Role.USER))


@given(owner=_IDS)
@settings(max_examples=100)
def test_임의_식별자로_스코프를_만들_수_없다(owner: str) -> None:
    """(e) 남의 UserId 를 알아도 그 사람의 스코프를 만들 수 없다."""
    with pytest.raises(TypeError):
        OwnerScope(UserId(owner))  # type: ignore[call-arg]
