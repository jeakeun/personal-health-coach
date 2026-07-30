"""키 보관 포트.

암호화 키는 **소스코드 · 설정 파일이 아닌 OS 자격증명 저장소**에 보관합니다
(NFR-02, C4=A). Windows 에서는 DPAPI 어댑터가 구현합니다.

⛔ 기동 시 키를 얻지 못하면 **애플리케이션을 시작하지 않습니다** (BR-ER-05).
   암호화 없이 건강 데이터를 기록하는 경로를 만들지 않기 위해서입니다.
   "키가 없으면 평문으로라도 저장" 은 이 코드베이스에 존재하지 않는 선택지입니다.
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["SecretStorePort"]


class SecretStorePort(Protocol):
    """OS 자격증명 저장소 추상화.

    ⚠ 반환된 키 바이트는 **호출 지점 밖으로 캐시·기록되지 않아야** 합니다.
    구현체도 내부에 보관하지 않습니다.
    """

    def ensure_key(self, name: str, *, size: int = 32) -> bytes:
        """키가 없으면 암호학적 난수로 생성하고, 있으면 기존 키를 반환한다.

        최초 기동 시 한 번 호출됩니다. **멱등**입니다 — 이미 있으면
        재생성하지 않습니다. 재생성하면 기존 암호문을 복호화할 수 없게 됩니다.

        Raises:
            StartupError: 저장소에 접근할 수 없는 경우.
        """
        ...

    def get_key(self, name: str) -> bytes:
        """기존 키를 조회한다.

        Raises:
            StartupError: 키가 없거나 저장소에 접근할 수 없는 경우.
        """
        ...
