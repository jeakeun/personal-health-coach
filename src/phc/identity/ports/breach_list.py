"""유출 비밀번호 목록 포트 (NFR-41, F6=A).

로컬 번들 파일을 오프라인 대조합니다. 외부 API(HIBP 등)를 쓰지 않는 이유:

- CON-02 가 "인터넷 없이도 동작" 을 요구합니다. 외부 조회에 의존하면
  네트워크가 없을 때 **회원가입 자체가 막힙니다**.
- 비밀번호 해시 앞자리가 네트워크로 나갑니다.

**범위 한계 (정직하게)**: 로컬 번들은 상위 N건만 담으므로 최신 유출 전량을
막지 못합니다. 오프라인 동작을 지키기 위한 의도적 절충입니다 (BR-PW-02).
"""

from __future__ import annotations

from typing import Protocol

from phc.shared import SecretStr

__all__ = ["BreachedPasswordListPort"]


class BreachedPasswordListPort(Protocol):
    def contains(self, password: SecretStr) -> bool:
        """유출 목록에 있는가.

        Raises:
            UndeterminedError: ⛔ 목록을 읽을 수 없는 경우.
                호출자는 가입·변경을 **거부**해야 합니다 (BR-PW-03).
                "목록을 못 읽었으니 통과" 는 이 코드베이스에 없는 선택지입니다.
        """
        ...

    @property
    def entry_count(self) -> int:
        """번들된 항목 수. NFR-1A-20(>= 10만 건) 검증에 사용됩니다."""
        ...
