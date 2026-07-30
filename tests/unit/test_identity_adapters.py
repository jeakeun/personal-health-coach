"""identity 실제 어댑터 테스트 (S26).

⚠ 다른 테스트는 속도 때문에 ``FakePasswordHasher`` 를 씁니다. 그렇게만 두면
   **"테스트는 통과하는데 실제 구현은 검증되지 않은"** 상태가 됩니다
   (Phase 1 의 F-05/06/07 과 같은 부류).

   이 파일이 진짜 Argon2id · 유출 목록 파일 · TOTP 를 검증합니다.
   Argon2id 64 MiB 는 의도적으로 느리므로 호출 횟수를 최소로 유지합니다.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phc.identity.adapters.argon2_hasher import MIN_MEMORY_KIB, Argon2PasswordHasher
from phc.identity.adapters.breach_list import (
    FileBreachedPasswordList,
    NullBreachedPasswordList,
)
from phc.identity.adapters.totp import PyotpTotpAdapter
from phc.shared import SecretStr, UndeterminedError

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

#: 테스트 전용 축소 파라미터. 실제 기본값(64 MiB)은 아래 예산 테스트에서만 씁니다.
_FAST = {"memory_kib": MIN_MEMORY_KIB, "time_cost": 1, "parallelism": 1}


# ---------------------------------------------------------------------------
# Argon2id (NFR-40, N3=A)
# ---------------------------------------------------------------------------
class TestArgon2PasswordHasher:
    def test_해시와_검증이_짝을_이룬다(self) -> None:
        hasher = Argon2PasswordHasher(**_FAST)
        password = SecretStr("correct-horse-battery")

        stored = hasher.hash(password)

        assert hasher.verify(password, stored)
        assert not hasher.verify(SecretStr("wrong-password-x"), stored)

    def test_같은_비밀번호도_매번_다른_해시가_된다(self) -> None:
        """솔트가 적용되는지 확인합니다."""
        hasher = Argon2PasswordHasher(**_FAST)
        password = SecretStr("correct-horse-battery")

        assert hasher.hash(password).encoded != hasher.hash(password).encoded

    def test_해시에_평문이_들어있지_않다(self) -> None:
        hasher = Argon2PasswordHasher(**_FAST)
        password = SecretStr("correct-horse-battery")

        assert "correct-horse-battery" not in hasher.hash(password).encoded

    def test_argon2id_알고리즘_식별자를_사용한다(self) -> None:
        hasher = Argon2PasswordHasher(**_FAST)
        assert hasher.hash(SecretStr("password-value")).encoded.startswith("$argon2id$")

    def test_손상된_해시는_검증에_실패하되_예외를_던지지_않는다(self) -> None:
        """⚠ 예외/정상 반환의 경로 차이가 타이밍 정보를 만들 수 있습니다."""
        hasher = Argon2PasswordHasher(**_FAST)
        from phc.shared import PasswordHash

        assert not hasher.verify(SecretStr("x" * 12), PasswordHash("not-a-valid-hash"))

    def test_파라미터를_올리면_재해시_대상이_된다(self) -> None:
        """BR-PW-07 — 파라미터 상향에 마이그레이션이 필요 없습니다."""
        weak = Argon2PasswordHasher(**_FAST)
        strong = Argon2PasswordHasher(memory_kib=MIN_MEMORY_KIB * 2, time_cost=2, parallelism=1)

        stored = weak.hash(SecretStr("correct-horse-battery"))

        assert not weak.needs_rehash(stored)
        assert strong.needs_rehash(stored)
        # 구버전 해시도 검증은 되어야 합니다 — 재해시는 로그인 성공 후입니다.
        assert strong.verify(SecretStr("correct-horse-battery"), stored)

    def test_해석할_수_없는_해시는_재해시_대상이다(self) -> None:
        from phc.shared import PasswordHash

        assert Argon2PasswordHasher(**_FAST).needs_rehash(PasswordHash("garbage"))

    def test_메모리_하한_아래로는_설정할_수_없다(self) -> None:
        """⭐ 성능 예산을 맞추더라도 이 아래로는 내리지 않습니다 (NFR-1A-16)."""
        with pytest.raises(ValueError, match="이상이어야 합니다"):
            Argon2PasswordHasher(memory_kib=MIN_MEMORY_KIB - 1)

    def test_더미_검증은_예외를_던지지_않는다(self) -> None:
        """BR-TH-12 — 계정이 없을 때 호출되므로 절대 죽으면 안 됩니다."""
        Argon2PasswordHasher(**_FAST).dummy_verify()

    @pytest.mark.slow
    def test_기본_파라미터가_성능_예산_안에_있다(self) -> None:
        """NFR-1A-05 — 해시 검증 <= 500ms.

        ⭐ 이 측정치가 파라미터 조정의 근거입니다 (nfr-requirements.md §2.1).
           150ms 를 크게 밑돌면 강도를 올릴 여지가 있다는 뜻입니다.
        """
        hasher = Argon2PasswordHasher()  # 실제 기본값: 64 MiB · t=3 · p=4
        password = SecretStr("correct-horse-battery")
        stored = hasher.hash(password)

        started = time.perf_counter()
        hasher.verify(password, stored)
        elapsed_ms = (time.perf_counter() - started) * 1000

        # 상한만 단언합니다. 하한은 기기마다 달라 단언 대상이 아니며,
        # 실측값은 운영에서 password.hash.duration 지표로 추적합니다.
        assert elapsed_ms <= 500, f"해시 검증이 예산을 초과했습니다: {elapsed_ms:.0f}ms"


# ---------------------------------------------------------------------------
# 유출 비밀번호 목록 (NFR-41, F6=A)
# ---------------------------------------------------------------------------
class TestFileBreachedPasswordList:
    @staticmethod
    def _write_list(tmp_path: Path, passwords: list[str]) -> Path:
        path = tmp_path / "breached.txt"
        digests = [
            hashlib.sha1(p.encode(), usedforsecurity=False).hexdigest().upper() for p in passwords
        ]
        path.write_text("\n".join(digests), encoding="utf-8")
        return path

    def test_목록에_있는_비밀번호를_찾는다(self, tmp_path: Path) -> None:
        path = self._write_list(tmp_path, ["password123", "qwerty12"])
        breach_list = FileBreachedPasswordList(path)

        assert breach_list.contains(SecretStr("password123"))
        assert not breach_list.contains(SecretStr("a-fresh-passphrase"))

    def test_항목_수를_보고한다(self, tmp_path: Path) -> None:
        """NFR-1A-20 검증(>= 10만 건)에 쓰입니다."""
        path = self._write_list(tmp_path, ["a" * 10, "b" * 10, "c" * 10])
        assert FileBreachedPasswordList(path).entry_count == 3

    def test_평문_비밀번호가_파일에_없다(self, tmp_path: Path) -> None:
        """해시로 보관하는 이유 — 저장소에 평문 목록을 두지 않습니다."""
        path = self._write_list(tmp_path, ["password123"])
        assert "password123" not in path.read_text(encoding="utf-8")

    def test_파일을_읽을_수_없으면_판정_불가로_처리한다(self, tmp_path: Path) -> None:
        """⛔ BR-PW-03 — '못 읽었으니 통과' 는 없는 선택지입니다."""
        missing = FileBreachedPasswordList(tmp_path / "does-not-exist.txt")

        with pytest.raises(UndeterminedError):
            missing.contains(SecretStr("any-password"))

    def test_한_번_읽은_뒤에는_캐시한다(self, tmp_path: Path) -> None:
        path = self._write_list(tmp_path, ["password123"])
        breach_list = FileBreachedPasswordList(path)

        assert breach_list.contains(SecretStr("password123"))
        path.unlink()  # 파일을 지워도
        assert breach_list.contains(SecretStr("password123"))  # 캐시로 동작


class TestNullBreachedPasswordList:
    def test_모든_비밀번호를_통과시킨다(self) -> None:
        """⚠ 개발·테스트 전용. 운영 조립에서 선택되면 NFR-1A-20 미충족입니다."""
        null_list = NullBreachedPasswordList()

        assert not null_list.contains(SecretStr("password123"))
        assert null_list.entry_count == 0


# ---------------------------------------------------------------------------
# TOTP (NFR-44, F5=A)
# ---------------------------------------------------------------------------
class TestPyotpTotpAdapter:
    def test_생성한_비밀키로_만든_코드가_검증된다(self) -> None:
        import pyotp

        adapter = PyotpTotpAdapter()
        secret = adapter.generate_secret()
        code = pyotp.TOTP(secret.reveal()).at(NOW)

        assert adapter.verify(secret, code, now=NOW)

    def test_틀린_코드는_거부된다(self) -> None:
        adapter = PyotpTotpAdapter()
        secret = adapter.generate_secret()

        assert not adapter.verify(secret, "000000", now=NOW)

    def test_같은_시간창의_코드는_재사용할_수_없다(self) -> None:
        """⭐ BR-MF-10 — 재생 공격 방지."""
        import pyotp

        adapter = PyotpTotpAdapter()
        secret = adapter.generate_secret()
        code = pyotp.TOTP(secret.reveal()).at(NOW)

        assert adapter.verify(secret, code, now=NOW)
        assert not adapter.verify(secret, code, now=NOW)

    def test_다음_시간창에서는_새_코드를_쓸_수_있다(self) -> None:
        import pyotp

        adapter = PyotpTotpAdapter()
        secret = adapter.generate_secret()
        later = NOW + timedelta(minutes=5)

        assert adapter.verify(secret, pyotp.TOTP(secret.reveal()).at(NOW), now=NOW)
        assert adapter.verify(secret, pyotp.TOTP(secret.reveal()).at(later), now=later)

    def test_등록_URI_에_발급자가_들어간다(self) -> None:
        adapter = PyotpTotpAdapter()
        uri = adapter.provisioning_uri(adapter.generate_secret(), "alice")

        assert uri.startswith("otpauth://totp/")
        assert "Personal%20Health%20Coach" in uri or "Personal Health Coach" in uri

    def test_비밀키가_매번_다르다(self) -> None:
        adapter = PyotpTotpAdapter()
        secrets_seen = {adapter.generate_secret().reveal() for _ in range(20)}
        assert len(secrets_seen) == 20
