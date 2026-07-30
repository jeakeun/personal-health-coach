"""유출 비밀번호 목록 어댑터 (S19, F6=A).

번들 파일 형식: SHA-1 대문자 16진 해시, 한 줄에 하나.
해시로 보관하는 이유는 저장소에 평문 비밀번호 목록을 두지 않기 위함입니다.

목록 파일은 ``scripts/build_breach_list.py`` 로 생성합니다.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from phc.shared import SecretStr, UndeterminedError

__all__ = ["FileBreachedPasswordList", "NullBreachedPasswordList"]


class FileBreachedPasswordList:
    """번들 파일을 메모리에 올려 대조한다.

    10만 건 x 40바이트 = 약 4 MB. 로컬 데스크톱에서 부담이 아닙니다.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._hashes: frozenset[str] | None = None

    def _load(self) -> frozenset[str]:
        if self._hashes is not None:
            return self._hashes
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            # ⛔ 목록을 못 읽으면 "통과" 가 아니라 "판정 불가" 입니다 (BR-PW-03).
            raise UndeterminedError(
                "breach_list",
                detail=f"유출 목록을 읽을 수 없습니다: {type(exc).__name__}",
            ) from exc

        self._hashes = frozenset(line.strip().upper() for line in lines if line.strip())
        return self._hashes

    def contains(self, password: SecretStr) -> bool:
        digest = hashlib.sha1(password.reveal().encode(), usedforsecurity=False).hexdigest()
        return digest.upper() in self._load()

    @property
    def entry_count(self) -> int:
        return len(self._load())


class NullBreachedPasswordList:
    """목록이 준비되지 않은 환경용.

    ⚠ **모든 비밀번호를 통과시킵니다.** 개발·테스트 전용이며, 운영 조립에서
    이 구현이 선택되면 NFR-1A-20 이 충족되지 않습니다. 조립 루트가 목록 파일
    부재를 경고하도록 합니다 (S37).
    """

    def contains(self, password: SecretStr) -> bool:
        return False

    @property
    def entry_count(self) -> int:
        return 0
