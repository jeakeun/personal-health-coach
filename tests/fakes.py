"""테스트 대역 (S26).

⭐ ``FakePasswordHasher`` 가 필요한 이유:
   Argon2id 64MiB 는 **의도적으로** 느립니다. 속성 테스트가 수백 케이스를
   돌 때 실제 해시를 쓰면 몇 분이 걸립니다. 포트를 둔 이유가 이것입니다
   (``phc.identity.ports.password``).

   실제 Argon2 어댑터는 별도 테스트에서 소수 케이스로만 검증합니다.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from phc.shared import CipherPurpose, PasswordHash, SecretStr

__all__ = ["FakeCipher", "FakePasswordHasher", "FakeTotp", "StubBreachList"]

_FAKE_PREFIX = "fake$v1$"
_WEAK_PREFIX = "fake$v0$"


class FakePasswordHasher:
    """빠른 결정론적 해시.

    ⚠ 운영에서 절대 쓰이지 않습니다. 조립 루트가 ``Argon2PasswordHasher`` 를
    사용하며, 이 클래스는 ``tests/`` 밖에서 import 되지 않습니다.

    ``legacy_params`` 로 만든 해시는 ``needs_rehash`` 가 참이 되어
    재해시 경로(BR-PW-07)를 검증할 수 있습니다.
    """

    def __init__(self, *, legacy: bool = False) -> None:
        self._prefix = _WEAK_PREFIX if legacy else _FAKE_PREFIX
        self.dummy_verify_calls = 0

    def hash(self, password: SecretStr) -> PasswordHash:
        digest = hashlib.sha256(password.reveal().encode()).hexdigest()
        return PasswordHash(f"{self._prefix}{digest}")

    def verify(self, password: SecretStr, stored: PasswordHash) -> bool:
        digest = hashlib.sha256(password.reveal().encode()).hexdigest()
        # 접두사(파라미터 세대)와 무관하게 다이제스트만 비교합니다 —
        # 실제 Argon2 도 구버전 파라미터 해시를 검증할 수 있어야 합니다.
        return stored.encoded.endswith(digest)

    def needs_rehash(self, stored: PasswordHash) -> bool:
        return not stored.encoded.startswith(_FAKE_PREFIX)

    def upgrade_params(self) -> None:
        """파라미터 세대를 올린다 — 실제 Argon2 파라미터 상향에 대응.

        이후 구버전 해시는 ``needs_rehash`` 가 참이 되어, 다음 로그인 성공 시
        재해시되는지 검증할 수 있습니다 (BR-PW-07).
        """
        self._prefix = _FAKE_PREFIX

    def dummy_verify(self) -> None:
        """호출 여부를 세어 BR-TH-12 준수를 검증합니다."""
        self.dummy_verify_calls += 1


class StubBreachList:
    """유출 목록 스텁.

    ``fail=True`` 이면 조회 자체가 실패해 ⛔ fail closed 경로를 검증합니다
    (BR-PW-03).
    """

    def __init__(self, *, breached: set[str] | None = None, fail: bool = False) -> None:
        self._breached = breached or set()
        self._fail = fail

    def contains(self, password: SecretStr) -> bool:
        if self._fail:
            raise OSError("유출 목록을 읽을 수 없습니다")
        return password.reveal() in self._breached

    @property
    def entry_count(self) -> int:
        return len(self._breached)


class FakeCipher:
    """XOR 기반 가짜 암호화. 암·복호화가 짝을 이루는지만 확인합니다."""

    KEY = 0x5A

    def encrypt(self, plain: bytes, purpose: CipherPurpose) -> bytes:
        return bytes(b ^ self.KEY for b in plain)

    def decrypt(self, cipher: bytes, purpose: CipherPurpose) -> bytes:
        return bytes(b ^ self.KEY for b in cipher)


class FakeTotp:
    """고정 코드 TOTP.

    ``valid_code`` 와 일치하면 통과합니다. 같은 코드의 재사용은
    실제 어댑터와 마찬가지로 거부합니다 (BR-MF-10).
    """

    def __init__(self, *, valid_code: str = "123456") -> None:
        self._valid_code = valid_code
        self._used: set[tuple[str, str]] = set()

    def generate_secret(self) -> SecretStr:
        return SecretStr("FAKESECRET234567")

    def provisioning_uri(self, secret: SecretStr, account_name: str) -> str:
        return f"otpauth://totp/{account_name}?secret=***"

    def verify(self, secret: SecretStr, code: str, *, now: datetime) -> bool:
        if code != self._valid_code:
            return False
        marker = (secret.reveal()[:4], f"{code}@{int(now.timestamp()) // 30}")
        if marker in self._used:
            return False
        self._used.add(marker)
        return True
