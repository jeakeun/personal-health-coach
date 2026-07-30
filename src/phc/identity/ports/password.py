"""비밀번호 해시 포트 (NFR-40).

포트로 둔 이유는 두 가지입니다.

1. **테스트 속도** — Argon2id 64MiB 는 의도적으로 느립니다. 속성 테스트가
   수백 케이스를 돌 때 실제 해시를 쓰면 몇 분이 걸립니다. 가짜 구현으로
   대체할 수 있어야 합니다.
2. **알고리즘 교체** — ``PasswordHash`` 에 알고리즘 식별자가 포함되므로
   ``needs_rehash`` 를 통한 점진 마이그레이션이 가능합니다 (BR-PW-07).
"""

from __future__ import annotations

from typing import Protocol

from phc.shared import PasswordHash, SecretStr

__all__ = ["PasswordHasherPort"]


class PasswordHasherPort(Protocol):
    """적응형 해시.

    ⚠ 구현체는 **평문을 저장·로깅하지 않아야** 합니다 (INV-AC-01).
    """

    def hash(self, password: SecretStr) -> PasswordHash: ...

    def verify(self, password: SecretStr, stored: PasswordHash) -> bool:
        """상수 시간 비교로 검증한다.

        ⚠ 검증 실패 시 예외를 던지지 않고 ``False`` 를 반환합니다.
        예외/정상 반환의 경로 차이가 타이밍 정보를 만들 수 있습니다.
        """
        ...

    def needs_rehash(self, stored: PasswordHash) -> bool:
        """저장된 해시의 파라미터가 현재 기준보다 낮은가 (BR-PW-07)."""
        ...

    def dummy_verify(self) -> None:
        """⭐ 계정이 없을 때 연산 시간을 맞추기 위한 더미 검증 (BR-TH-12).

        이것이 없으면 존재하지 않는 사용자명일 때만 응답이 빨라지고,
        **응답 시간만으로 유효한 사용자명 목록을 만들 수 있습니다.**
        지연(BR-TH-02)이 편차를 덮지만, 연산 시간 자체를 맞추는 것이 1차입니다.
        """
        ...
