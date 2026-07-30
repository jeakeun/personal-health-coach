"""감사 기록 포트 — append-only.

⭐ **갱신·삭제 연산이 이 인터페이스에 존재하지 않습니다** (NFR-10, BR-AU-01).

    "구현하지 않았다"와 "인터페이스에 없다"는 다릅니다. 전자는 나중에 누군가
    필요해서 추가합니다. 후자는 추가하려면 이 파일을 열어야 하고, 그 변경이
    리뷰에 드러납니다.

    감사 로그의 정리(1년 경과분 아카이브 이관)는 애플리케이션이 아니라
    운영 스크립트가 수행합니다 (F9=A).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from phc.operations.domain.audit import AuditEntry, AuditEventType
from phc.shared import UserId

__all__ = ["AuditFilter", "AuditTrailPort"]


@dataclass(frozen=True, slots=True)
class AuditFilter:
    """감사 조회 조건."""

    event_types: frozenset[AuditEventType] | None = None
    actor_user_id: UserId | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = 100


class AuditTrailPort(Protocol):
    """감사 기록 저장소.

    ``append`` 와 조회만 있습니다. ``update`` · ``delete`` 는 없습니다.
    """

    def append(self, entry: AuditEntry) -> AuditEntry:
        """기록을 추가하고 ``seq`` 가 부여된 엔트리를 반환한다.

        Raises:
            DomainError: 기록에 실패한 경우.
                ⚠ 호출자는 이 실패를 삼키면 안 됩니다. 보안 관련 작업은
                기록되지 않으면 일어나지 않은 것으로 다룹니다 (BR-AU-08).
        """
        ...

    def query(self, criteria: AuditFilter) -> list[AuditEntry]:
        """조건에 맞는 기록을 최신순으로 조회한다."""
        ...

    def count_since(self, event_type: AuditEventType, since: datetime) -> int:
        """시간 창 안의 발생 횟수. 누적 기준 알림 판정에 사용됩니다."""
        ...

    def max_seq(self) -> int:
        """마지막 ``seq``. 결번 검증에 사용됩니다 (INV-AU-03)."""
        ...
