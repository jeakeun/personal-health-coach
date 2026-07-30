"""🔬 PBT 속성 2 — 평문 비밀번호 부재 (PBT-03).

**진술**: 임의의 연산 시퀀스(가입 · 로그인 · 변경 · 재설정 · 부트스트랩 ·
MFA 등록) 후, 저장소의 어떤 ``Account`` · ``MfaRecoveryCode`` 레코드에도
입력 평문과 일치하거나 가역 변환으로 복원 가능한 값이 존재하지 않는다.

**확장 (계획 §10 속성 2)**:
    저장소뿐 아니라 **감사 로그와 구조화 로그 출력에도 동일 검사**를
    적용합니다. AC-17("임시 비밀번호가 저장소·설정파일·로그 어디에도 평문으로
    남지 않는다")이 요구하는 범위가 그것입니다.

반례가 잡는 것:
    디버그 필드에 평문이 새는 버그 · 임시 비밀번호가 감사에 남는 버그

근거: US-43 · US-46 · NFR-40 · NFR-45 · NFR-1A-22 · AC-17
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from phc.operations.domain.audit import AuditEventType, AuditOutcome
from phc.operations.ports.audit import AuditFilter
from phc.shared import AuthContext, Role, SecretStr
from tests.conftest import IdentityFixture, build_identity

pytestmark = pytest.mark.property

#: 8자 이상(정책 통과) · 인쇄 가능 문자.
_PASSWORDS = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=8,
    max_size=40,
)

_USERNAMES = st.sampled_from(["alice", "bob", "carol"])


#: 타입 이름 · 필드 이름 — repr 에 항상 등장하는 구조 문자열.
_MANUAL_TOKENS = frozenset(
    {
        "must_change_password",
        "PasswordHash",
        "password_hash",
        "SecretStr",
        "SessionToken",
        "MfaRecoveryCode",
        "MfaEnrollment",
        "RecoveryCodeId",
        "AccountSummary",
        "AuditEventType",
        "AuditOutcome",
        "AuditEntry",
        "correlation_id",
        "actor_user_id",
        "secret_cipher",
        "display_name",
        "occurred_at",
        "target_ref",
        "code_hash",
        "Username",
        "Account",
        "UserId",
    }
)

#: ⚠ **탐지기의 거짓 양성을 막는 장치**입니다.
#:
#:    Hypothesis 가 두 번 잡아냈습니다.
#:      1. ``password='Password'``  -> 타입 이름 ``PasswordHash`` 와 겹침
#:      2. ``password='password'``  -> 감사 이벤트 값 ``password_changed`` 와 겹침
#:
#:    둘 다 저장소에 평문이 남아서가 아니라 **구조 문자열과 겹쳐서** 난
#:    실패였습니다. 열거형 이름·값은 계속 늘어나므로 손으로 적지 않고
#:    **프로그램으로 수집**합니다 — 새 이벤트가 추가돼도 자동으로 덮입니다.
#:
#:    길이 내림차순으로 지웁니다. 짧은 토큰을 먼저 지우면 긴 토큰의 일부가
#:    사라져 남은 조각이 오탐을 만듭니다.
_STRUCTURAL_TOKENS: tuple[str, ...] = tuple(
    sorted(
        _MANUAL_TOKENS
        | {e.name for e in AuditEventType}
        | {e.value for e in AuditEventType}
        | {e.name for e in AuditOutcome}
        | {e.value for e in AuditOutcome}
        | {r.name for r in Role}
        | {r.value for r in Role},
        key=len,
        reverse=True,
    )
)


def _strip_structure(text: str) -> str:
    """구조 문자열을 제거해 데이터만 남긴다."""
    for token in _STRUCTURAL_TOKENS:
        text = text.replace(token, "")
    return text


def _all_stored_text(fx: IdentityFixture) -> str:
    """저장소 전체를 문자열로 훑는다.

    필드를 하나씩 검사하면 나중에 추가된 필드를 놓칩니다. 통째로 훑어야
    "어딘가에 새고 있다" 를 잡을 수 있습니다.
    """
    chunks: list[str] = []

    for account in fx.accounts.list_all():
        chunks.append(repr(account))
        chunks.append(account.password_hash.encoded)
        chunks.append(account.display_name)

        for code in fx.mfa_repo.list_recovery_codes(account.id):
            chunks.append(repr(code))
            chunks.append(code.code_hash.encoded)

        enrollment = fx.mfa_repo.get_enrollment(account.id)
        if enrollment is not None:
            chunks.append(repr(enrollment))
            chunks.append(enrollment.secret_cipher.decode("latin-1"))

    return "\n".join(chunks)


def _all_audit_text(fx: IdentityFixture) -> str:
    """감사 로그 전체를 문자열로 훑는다 (AC-17 확장)."""
    return "\n".join(
        repr(e) + str(e.detail) + str(e.target_ref) for e in fx.audit.query(AuditFilter(limit=500))
    )


@given(password=_PASSWORDS, username=_USERNAMES)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_가입한_비밀번호가_저장소에_남지_않는다(password: str, username: str) -> None:
    fx = build_identity()
    fx.auth.sign_up(username, SecretStr(password))

    assert password not in _strip_structure(_all_stored_text(fx))
    assert password not in _strip_structure(_all_audit_text(fx))


@given(first=_PASSWORDS, second=_PASSWORDS, username=_USERNAMES)
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_변경_전후_어느_비밀번호도_남지_않는다(first: str, second: str, username: str) -> None:
    fx = build_identity()
    result = fx.auth.sign_up(username, SecretStr(first))
    ctx = AuthContext(result.user_id, Role.USER)

    if first != second:
        fx.auth.change_password(ctx, SecretStr(first), SecretStr(second))

    stored = _strip_structure(_all_stored_text(fx))
    audit = _strip_structure(_all_audit_text(fx))

    assert first not in stored
    assert second not in stored
    assert first not in audit
    assert second not in audit


@given(seed=st.lists(_USERNAMES, min_size=0, max_size=3, unique=True))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_부트스트랩_임시_비밀번호가_어디에도_남지_않는다(seed: list[str]) -> None:
    """⭐ AC-17 — 저장소 · 감사 · 어디에도."""
    fx = build_identity()
    for name in seed:
        fx.auth.sign_up(name, SecretStr("seed-password-value"))

    outcome = fx.bootstrapper.bootstrap()
    assert outcome.console_notice is not None
    temporary = outcome.console_notice.reveal()

    assert temporary not in _strip_structure(_all_stored_text(fx))
    assert temporary not in _strip_structure(_all_audit_text(fx))


@given(password=_PASSWORDS)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_관리자_재설정_임시_비밀번호도_남지_않는다(password: str) -> None:
    fx = build_identity()
    fx.bootstrapper.bootstrap()
    admin = fx.account("admin")
    admin_ctx = AuthContext(admin.id, Role.ADMIN)

    target = fx.auth.sign_up("alice", SecretStr(password))
    reset = fx.admin.reset_password(admin_ctx, target.user_id)
    temporary = reset.temporary_password.reveal()

    stored = _strip_structure(_all_stored_text(fx))
    audit = _strip_structure(_all_audit_text(fx))

    assert temporary not in stored
    assert temporary not in audit
    assert password not in stored


@given(password=_PASSWORDS)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_MFA_비밀키와_복구_코드가_평문으로_남지_않는다(password: str) -> None:
    fx = build_identity()
    result = fx.auth.sign_up("alice", SecretStr(password))

    challenge = fx.mfa.begin_enrollment(result.user_id, "alice")
    bundle = fx.mfa.confirm_enrollment(result.user_id, "123456")

    stored = _strip_structure(_all_stored_text(fx))
    assert challenge.secret.reveal() not in stored
    for code in bundle.codes:
        assert code.reveal() not in stored
