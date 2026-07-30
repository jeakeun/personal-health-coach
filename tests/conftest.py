"""공용 픽스처 (S26).

identity 서비스는 의존이 많아 조립 코드가 테스트마다 반복됩니다.
``IdentityFixture`` 가 그 조립을 한 곳에 모읍니다 — 실제 조립 루트(S37)의
축소판이기도 합니다.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from hypothesis import HealthCheck, Verbosity, settings

from phc.identity.adapters.in_memory import (
    InMemoryAccountRepository,
    InMemoryMfaRepository,
    InMemorySessionRepository,
    InMemoryThrottleRepository,
)
from phc.identity.domain.account import Account
from phc.identity.services.admin import AdminService
from phc.identity.services.authentication import AuthService
from phc.identity.services.authorization import OwnershipAuthorizer, RoleAuthorizer
from phc.identity.services.bootstrap import AdminBootstrapper
from phc.identity.services.mfa import MfaEnroller
from phc.identity.services.passwords import PasswordPolicy
from phc.identity.services.sessions import SessionManager
from phc.identity.services.throttling import LoginThrottle
from phc.operations.adapters.in_memory import InMemoryAlertStore, InMemoryAuditTrail
from phc.operations.services.alerting import AlertDispatcher
from phc.operations.services.metrics import MetricsRegistry
from phc.shared import Username
from phc.shared.ports.clock import FixedClock
from tests.fakes import FakeCipher, FakePasswordHasher, FakeTotp, StubBreachList

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Hypothesis 프로파일 (S02, NFR-1A-35 · NFR-27)
#
# ⚠ 발견 사항 F-27: S02 는 "Hypothesis 프로파일(shrinking·시드 출력)" 을
#    설정했다고 기록했으나 `register_profile` 이 어디에도 없었습니다.
#    F-05/06/07/17/18/20 과 같은 부류(일곱 번째) — 설정했다고 적혀 있으나 실제로는
#    적용되지 않은 상태입니다. 실제로 두 가지가 드러났습니다.
#
#    1. `deadline` 기본값 200ms 가 켜져 있어 **첫 실행 웜업(253ms)이 실패로**
#       나타났습니다. 속성 테스트는 **불변식**을 검증하지 성능을 재지 않습니다 —
#       성능 예산은 `test_identity_adapters.py` 가 따로 측정합니다.
#       시간 기반 실패는 재현 불가능한 CI 간헐 실패를 만들 뿐입니다.
#
#    2. `print_blob` 이 꺼져 있어 실패해도 **재현 시드가 출력되지 않았습니다.**
#       NFR-27(재현 가능성)의 판정 수단이 빠져 있던 셈입니다.
# ---------------------------------------------------------------------------
settings.register_profile(
    "phc",
    deadline=None,
    # ⭐ 실패 시 @reproduce_failure 블롭을 출력합니다. 시드 없이 실패하면
    #    반례를 다시 만들 수 없습니다 (NFR-27).
    print_blob=True,
    # 축소(shrinking)는 기본 동작이며, 반례를 최소 형태로 줄여 보고합니다.
    # 느린 예시 생성 자체는 실패 사유가 아닙니다.
    suppress_health_check=[HealthCheck.too_slow],
    verbosity=Verbosity.normal,
)
settings.load_profile("phc")


@dataclass
class IdentityFixture:
    """조립된 identity 서비스 묶음."""

    clock: FixedClock
    accounts: InMemoryAccountRepository
    sessions_repo: InMemorySessionRepository
    throttle_repo: InMemoryThrottleRepository
    mfa_repo: InMemoryMfaRepository
    audit: InMemoryAuditTrail
    alert_store: InMemoryAlertStore
    metrics: MetricsRegistry
    hasher: FakePasswordHasher
    totp: FakeTotp
    sessions: SessionManager
    throttle: LoginThrottle
    mfa: MfaEnroller
    policy: PasswordPolicy
    roles: RoleAuthorizer
    ownership: OwnershipAuthorizer
    auth: AuthService
    admin: AdminService
    bootstrapper: AdminBootstrapper
    slept: list[float]

    def account(self, username: str) -> Account:
        """사용자명으로 계정을 가져온다. 없으면 즉시 실패시킵니다."""
        found = self.accounts.find_by_username(Username.parse(username))
        if found is None:
            raise AssertionError(f"계정을 찾을 수 없습니다: {username}")
        return found


def build_identity(
    *,
    breached: set[str] | None = None,
    breach_list_fails: bool = False,
    legacy_hasher: bool = False,
) -> IdentityFixture:
    clock = FixedClock(NOW)
    accounts = InMemoryAccountRepository()
    sessions_repo = InMemorySessionRepository()
    throttle_repo = InMemoryThrottleRepository()
    mfa_repo = InMemoryMfaRepository()
    audit = InMemoryAuditTrail()
    alert_store = InMemoryAlertStore()
    metrics = MetricsRegistry()
    hasher = FakePasswordHasher(legacy=legacy_hasher)
    totp = FakeTotp()
    cipher = FakeCipher()

    # 테스트가 실제로 잠들지 않도록 지연을 기록만 합니다.
    slept: list[float] = []

    alerts = AlertDispatcher(store=alert_store, channels=[], clock=clock)
    sessions = SessionManager(repository=sessions_repo, clock=clock)
    throttle = LoginThrottle(
        repository=throttle_repo, clock=clock, sleep=lambda seconds: slept.append(seconds)
    )
    mfa = MfaEnroller(repository=mfa_repo, totp=totp, cipher=cipher, hasher=hasher, clock=clock)
    policy = PasswordPolicy(breach_list=StubBreachList(breached=breached, fail=breach_list_fails))
    roles = RoleAuthorizer(audit=audit, clock=clock, metrics=metrics)
    ownership = OwnershipAuthorizer(audit=audit, clock=clock, metrics=metrics)

    auth = AuthService(
        accounts=accounts,
        hasher=hasher,
        policy=policy,
        throttle=throttle,
        sessions=sessions,
        mfa=mfa,
        audit=audit,
        alerts=alerts,
        clock=clock,
        metrics=metrics,
    )
    admin = AdminService(
        accounts=accounts,
        sessions=sessions,
        roles=roles,
        hasher=hasher,
        audit=audit,
        alerts=alerts,
        clock=clock,
    )
    bootstrapper = AdminBootstrapper(accounts=accounts, hasher=hasher, audit=audit, clock=clock)

    return IdentityFixture(
        clock=clock,
        accounts=accounts,
        sessions_repo=sessions_repo,
        throttle_repo=throttle_repo,
        mfa_repo=mfa_repo,
        audit=audit,
        alert_store=alert_store,
        metrics=metrics,
        hasher=hasher,
        totp=totp,
        sessions=sessions,
        throttle=throttle,
        mfa=mfa,
        policy=policy,
        roles=roles,
        ownership=ownership,
        auth=auth,
        admin=admin,
        bootstrapper=bootstrapper,
        slept=slept,
    )


@pytest.fixture
def identity() -> IdentityFixture:
    return build_identity()
