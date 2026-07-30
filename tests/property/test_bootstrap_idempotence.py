"""🔬 PBT 속성 1 — 부트스트랩 멱등성 (PBT-04).

**진술**: 임의의 초기 상태 ``s`` 에 대해 ``bootstrap(bootstrap(s))`` 의
계정 집합은 ``bootstrap(s)`` 의 계정 집합과 같다.

검사:
    관리자 계정 수 불변 · password_hash 불변 · created_at 불변
    · 두 번째 호출의 console_notice 가 None

반례가 잡는 것:
    재기동마다 관리자 비밀번호가 재설정되는 버그 · 관리자 중복 생성

근거: US-46 · BR-BS-02 · AC-17

⚠ 의도적으로 남긴 성질:
    활성 관리자가 **0명이면** 부트스트랩이 다시 실행됩니다. 정상 경로에서는
    BR-AD-03(관리자 0명 방지)이 그 상태를 막지만, DB 를 직접 수정해 도달하면
    **복구 수단으로 동작**합니다 (런북 R2). 이 테스트는 그 경계를 함께
    확인합니다.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phc.identity.services.bootstrap import BOOTSTRAP_USERNAME
from phc.shared import Role, SecretStr, Username
from tests.conftest import IdentityFixture, build_identity

pytestmark = pytest.mark.property

_USERNAMES = st.lists(
    st.sampled_from(["alice", "bob", "carol", "dave"]), min_size=0, max_size=4, unique=True
)
_PASSWORD = SecretStr("seed-password-value")


def _seed(fx: IdentityFixture, usernames: list[str]) -> None:
    """임의의 일반 사용자들이 이미 가입된 상태를 만든다."""
    for name in usernames:
        fx.auth.sign_up(name, _PASSWORD)


def _snapshot(fx: IdentityFixture) -> list[tuple[str, str, str, str]]:
    """비교 가능한 계정 집합 표현."""
    return sorted(
        (
            a.username.normalized,
            a.password_hash.encoded,
            a.role.value,
            a.created_at.isoformat(),
        )
        for a in fx.accounts.list_all()
    )


@given(seed=_USERNAMES)
@settings(max_examples=100)
def test_두_번_호출해도_계정_집합이_같다(seed: list[str]) -> None:
    """⭐ 속성 1 의 본체."""
    fx = build_identity()
    _seed(fx, seed)

    first = fx.bootstrapper.bootstrap()
    after_first = _snapshot(fx)

    second = fx.bootstrapper.bootstrap()
    after_second = _snapshot(fx)

    assert first.created is True
    assert second.created is False
    assert second.console_notice is None
    assert after_first == after_second


@given(seed=_USERNAMES, times=st.integers(min_value=2, max_value=6))
@settings(max_examples=100)
def test_여러_번_재기동해도_불변이다(seed: list[str], times: int) -> None:
    """재기동이 반복되는 실제 상황."""
    fx = build_identity()
    _seed(fx, seed)

    fx.bootstrapper.bootstrap()
    baseline = _snapshot(fx)

    for _ in range(times):
        outcome = fx.bootstrapper.bootstrap()
        assert not outcome.created
        assert outcome.console_notice is None

    assert _snapshot(fx) == baseline


@given(seed=_USERNAMES)
@settings(max_examples=100)
def test_관리자_수가_늘어나지_않는다(seed: list[str]) -> None:
    fx = build_identity()
    _seed(fx, seed)

    for _ in range(5):
        fx.bootstrapper.bootstrap()

    admins = [a for a in fx.accounts.list_all() if a.role is Role.ADMIN]
    assert len(admins) == 1
    assert admins[0].username == Username.parse(BOOTSTRAP_USERNAME)


@given(seed=_USERNAMES)
@settings(max_examples=50)
def test_활성_관리자가_0명이면_복구_수단으로_동작한다(seed: list[str]) -> None:
    """⚠ 런북 R2 가 의존하는 성질 — DB 직접 수정으로만 도달하는 상태."""
    fx = build_identity()
    _seed(fx, seed)
    fx.bootstrapper.bootstrap()

    admin = fx.account(BOOTSTRAP_USERNAME)
    fx.accounts.save(admin.with_active(False, now=fx.clock.now()))

    recovered = fx.bootstrapper.bootstrap()

    assert recovered.created
    assert recovered.console_notice is not None
    assert fx.accounts.count_active_admins() == 1
