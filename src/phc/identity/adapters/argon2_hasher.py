"""Argon2id 해시 어댑터 (S19, NFR-40, N3=A).

파라미터: memory 64 MiB · time 3 · parallelism 4

⭐ 이 값은 고정 상수가 아니라 **성능 예산에 맞춰 조정되는 값**입니다
   (nfr-requirements.md §2.1). 실측이 150ms 를 밑돌면 강도를 올리고,
   500ms 를 넘으면 낮춥니다 — 단 memory 32 MiB 미만으로는 내리지 않습니다.

   조정 후에는 ``needs_rehash`` 가 참이 되어 다음 로그인 성공 시 자동으로
   재해시됩니다 (BR-PW-07). 즉 파라미터 변경에 마이그레이션이 필요 없습니다.
"""

from __future__ import annotations

from typing import Final

from argon2 import PasswordHasher as _Argon2
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from phc.shared import PasswordHash, SecretStr

__all__ = ["MIN_MEMORY_KIB", "Argon2PasswordHasher"]

#: 이 아래로는 내리지 않습니다. 메모리 하드 특성이 사라집니다.
MIN_MEMORY_KIB: Final = 32 * 1024

#: 계정이 없을 때 시간을 맞추기 위한 더미 해시 (BR-TH-12).
#: 모듈 로드 시 한 번 만들어 두고 재사용합니다.
_DUMMY_PASSWORD: Final = "dummy-password-for-timing-equalisation"  # noqa: S105


class Argon2PasswordHasher:
    """Argon2id 구현."""

    def __init__(
        self,
        *,
        memory_kib: int = 64 * 1024,
        time_cost: int = 3,
        parallelism: int = 4,
    ) -> None:
        if memory_kib < MIN_MEMORY_KIB:
            raise ValueError(
                f"Argon2id memory 는 {MIN_MEMORY_KIB} KiB 이상이어야 합니다. "
                f"성능 예산을 맞추더라도 이 아래로는 내리지 않습니다 (NFR-1A-16)."
            )
        self._hasher = _Argon2(
            memory_cost=memory_kib,
            time_cost=time_cost,
            parallelism=parallelism,
        )
        self._dummy_hash = self._hasher.hash(_DUMMY_PASSWORD)

    def hash(self, password: SecretStr) -> PasswordHash:
        return PasswordHash(self._hasher.hash(password.reveal()))

    def verify(self, password: SecretStr, stored: PasswordHash) -> bool:
        try:
            return self._hasher.verify(stored.encoded, password.reveal())
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            # 예외를 밖으로 던지지 않습니다 — 정상/실패의 경로 차이가
            # 타이밍 정보를 만들 수 있습니다.
            return False

    def needs_rehash(self, stored: PasswordHash) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored.encoded)
        except InvalidHashError:
            # 해석할 수 없는 해시는 재해시 대상으로 봅니다.
            return True

    def dummy_verify(self) -> None:
        """⭐ 계정이 없을 때도 같은 시간을 쓰게 합니다 (BR-TH-12).

        이것이 없으면 존재하지 않는 사용자명일 때만 응답이 빨라지고,
        응답 시간만으로 유효한 사용자명 목록을 만들 수 있습니다.
        """
        try:
            self._hasher.verify(self._dummy_hash, "wrong-password")
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
