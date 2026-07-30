"""``OwnerScope`` — 경계 B 의 타입 수준 보장 테스트 (S08).

이 테스트가 지키는 것은 US-42 · US-48 · RSK-10 입니다.
여기가 깨지면 1B 이후 모든 건강 데이터 격리가 무너집니다.
"""

from __future__ import annotations

import pytest

from phc.shared import AuthContext, OwnerScope, Role, UserId


@pytest.fixture
def alice() -> AuthContext:
    return AuthContext(subject_id=UserId("alice-id"), role=Role.USER)


@pytest.fixture
def admin() -> AuthContext:
    return AuthContext(subject_id=UserId("admin-id"), role=Role.ADMIN)


class TestOwnerScopeConstruction:
    def test_직접_생성할_수_없다(self) -> None:
        """⭐ 임의의 UserId 로 스코프를 만들 수 있으면 경계 B 가 무의미해진다."""
        with pytest.raises(TypeError, match="직접 생성할 수 없습니다"):
            OwnerScope(UserId("victim-id"))  # type: ignore[call-arg]

    def test_잘못된_열쇠로도_생성할_수_없다(self) -> None:
        with pytest.raises(TypeError):
            OwnerScope(UserId("victim-id"), construction_key=object())

    def test_유일한_생성_경로는_for_subject_이다(self, alice: AuthContext) -> None:
        scope = OwnerScope.for_subject(alice)
        assert scope.owner_id == alice.subject_id

    def test_for_subject_는_UserId_가_아니라_AuthContext_를_받는다(self) -> None:
        """남의 UserId 를 알아도 그 사람의 스코프를 만들 수 없다."""
        with pytest.raises(AttributeError):
            OwnerScope.for_subject(UserId("victim-id"))  # type: ignore[arg-type]


class TestOwnerScopeIsRoleAgnostic:
    def test_관리자도_자기_자신의_스코프만_얻는다(self, admin: AuthContext) -> None:
        """⭐ US-48 — 관리자 권한은 계정 도메인에만 미친다."""
        scope = OwnerScope.for_subject(admin)
        assert scope.owner_id == admin.subject_id

    def test_같은_주체라면_역할이_달라도_같은_스코프가_나온다(self) -> None:
        """소유권 판정에 역할이 개입하지 않음을 스코프 수준에서 확인한다."""
        uid = UserId("same-person")
        as_user = OwnerScope.for_subject(AuthContext(uid, Role.USER))
        as_admin = OwnerScope.for_subject(AuthContext(uid, Role.ADMIN))
        assert as_user == as_admin

    def test_다른_주체의_스코프는_같지_않다(self, alice: AuthContext, admin: AuthContext) -> None:
        assert OwnerScope.for_subject(alice) != OwnerScope.for_subject(admin)


class TestOwnerScopeValueSemantics:
    def test_읽기_전용이다(self, alice: AuthContext) -> None:
        scope = OwnerScope.for_subject(alice)
        with pytest.raises(AttributeError):
            scope.owner_id = UserId("other")  # type: ignore[misc]

    def test_해시_가능하다(self, alice: AuthContext) -> None:
        scope = OwnerScope.for_subject(alice)
        assert {scope, OwnerScope.for_subject(alice)} == {scope}

    def test_로그_표현에_소유자_식별자만_담긴다(self, alice: AuthContext) -> None:
        scope = OwnerScope.for_subject(alice)
        assert "alice-id" in scope.__redacted_repr__()
