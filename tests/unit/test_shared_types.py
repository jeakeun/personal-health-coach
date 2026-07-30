"""shared 값 타입 불변식 테스트 (S08)."""

from __future__ import annotations

import pytest

from phc.shared import (
    AuthContext,
    PasswordHash,
    Role,
    SafetyVerdict,
    SecretStr,
    SessionToken,
    SupportsRedactedRepr,
    UserId,
    Username,
)


# ---------------------------------------------------------------------------
# Username — 판정은 정규화 값으로, 표시는 원본으로 (INV-AC-02)
# ---------------------------------------------------------------------------
class TestUsername:
    @pytest.mark.parametrize(
        ("raw_a", "raw_b"),
        [
            ("admin", "Admin"),
            ("Alice", "  alice  "),
            ("BOB", "bob"),
        ],
    )
    def test_대소문자와_공백_차이는_같은_사용자명으로_판정된다(
        self, raw_a: str, raw_b: str
    ) -> None:
        """'Admin' 과 'admin' 이 서로 다른 계정이 되는 사고를 막는다."""
        assert Username.parse(raw_a) == Username.parse(raw_b)

    def test_유니코드_정규화가_적용된다(self) -> None:
        # 전각 문자를 의도적으로 사용합니다 — NFKC 정규화가 실제로 동작하는지가
        # 이 테스트의 전부이므로, 린터의 "모호한 문자" 경고를 여기서만 끕니다.
        fullwidth = "ｕｓｅｒ１"  # noqa: RUF001
        assert Username.parse(fullwidth) == Username.parse("user1")

    @pytest.mark.parametrize("raw", ["ab", "a" * 33, "user name", "user@host", "사용자!"])
    def test_허용되지_않는_사용자명은_거부된다(self, raw: str) -> None:
        with pytest.raises(ValueError):
            Username.parse(raw)

    @pytest.mark.parametrize("raw", ["admin", "ADMIN", "Administrator", "root", "system"])
    def test_예약어는_예약된_것으로_판정된다(self, raw: str) -> None:
        """자유 가입이므로 부트스트랩 전 admin 선점을 막아야 한다 (BR-BS-10)."""
        assert Username.parse(raw).is_reserved()

    def test_일반_사용자명은_예약어가_아니다(self) -> None:
        assert not Username.parse("alice").is_reserved()


# ---------------------------------------------------------------------------
# SecretStr — 평문이 문자열화 경로로 새지 않는다 (NFR-04, NFR-1A-22)
# ---------------------------------------------------------------------------
class TestSecretStr:
    SECRET = "correct-horse-battery-staple"

    def test_str_repr_format_어디에도_평문이_나타나지_않는다(self) -> None:
        secret = SecretStr(self.SECRET)

        rendered = [
            str(secret),
            repr(secret),
            f"{secret}",
            f"{secret!r}",
            f"{secret!s}",
            "{}".format(secret),  # noqa: UP032 - 포맷 경로를 명시적으로 검증
        ]

        for text in rendered:
            assert self.SECRET not in text
            assert "***" in text

    def test_reveal_로만_평문을_얻을_수_있다(self) -> None:
        assert SecretStr(self.SECRET).reveal() == self.SECRET

    def test_같은_값끼리_비교할_수_있다(self) -> None:
        assert SecretStr(self.SECRET) == SecretStr(self.SECRET)
        assert SecretStr(self.SECRET) != SecretStr("other")

    def test_원시_문자열과는_비교되지_않는다(self) -> None:
        """암묵 비교를 허용하면 타입 분리의 의미가 없어진다."""
        assert SecretStr(self.SECRET) != self.SECRET

    def test_길이와_참거짓은_노출해도_된다(self) -> None:
        assert len(SecretStr("abc")) == 3
        assert bool(SecretStr("abc"))
        assert not bool(SecretStr(""))


# ---------------------------------------------------------------------------
# PasswordHash / SessionToken — 마스킹
# ---------------------------------------------------------------------------
class TestOpaqueTypes:
    def test_PasswordHash_는_인코딩_값을_노출하지_않는다(self) -> None:
        h = PasswordHash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")
        assert "argon2" not in str(h)
        assert "argon2" not in repr(h)
        assert h.encoded.startswith("$argon2id$")  # 필요한 곳에서는 접근 가능

    def test_SessionToken_은_원문을_노출하지_않는다(self) -> None:
        token = SessionToken.generate()
        assert token.value not in str(token)
        assert token.value not in repr(token)

    def test_SessionToken_은_충분한_엔트로피를_갖는다(self) -> None:
        """NFR-1A-17 — 128비트 이상. token_urlsafe(32) = 256비트."""
        tokens = {SessionToken.generate().value for _ in range(100)}
        assert len(tokens) == 100  # 충돌 없음
        assert all(len(t) >= 32 for t in tokens)


# ---------------------------------------------------------------------------
# Redactable — 민감 타입은 로그 경로에 진입할 수 없다 (BR-AU-02)
# ---------------------------------------------------------------------------
class TestRedactable:
    def test_민감_타입은_안전_표현을_제공하지_않는다(self) -> None:
        """⭐ 이것이 로그 인자로 전달되지 못하게 하는 근거다."""
        assert not isinstance(SecretStr("x"), SupportsRedactedRepr)
        assert not isinstance(PasswordHash("$argon2id$..."), SupportsRedactedRepr)
        assert not isinstance(SessionToken("tok"), SupportsRedactedRepr)

    def test_민감_타입은_원시_타입도_아니다(self) -> None:
        """원시 타입 하위 클래스였다면 union 을 통해 통과했을 것이다."""
        for value in (SecretStr("x"), PasswordHash("$a$"), SessionToken("t")):
            assert not isinstance(value, str | int | float | bool)

    def test_도메인_타입은_안전_표현을_제공한다(self) -> None:
        assert isinstance(UserId.generate(), SupportsRedactedRepr)
        assert isinstance(Username.parse("alice"), SupportsRedactedRepr)
        assert isinstance(Role.USER, SupportsRedactedRepr)


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------
class TestAuthContext:
    def test_불변이다(self) -> None:
        ctx = AuthContext(subject_id=UserId.generate(), role=Role.USER)
        with pytest.raises(AttributeError):
            ctx.role = Role.ADMIN  # type: ignore[misc]

    def test_관리자_여부를_판별한다(self) -> None:
        uid = UserId.generate()
        assert AuthContext(uid, Role.ADMIN).is_admin
        assert not AuthContext(uid, Role.USER).is_admin


# ---------------------------------------------------------------------------
# SafetyVerdict — 판정 불가는 통과가 아니다 (NFR-09)
# ---------------------------------------------------------------------------
class TestSafetyVerdict:
    def test_ALLOWED_만_통과한다(self) -> None:
        assert SafetyVerdict.ALLOWED.passes
        assert not SafetyVerdict.BLOCKED.passes
        assert not SafetyVerdict.UNDETERMINED.passes
