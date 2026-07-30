"""백업 메타데이터 저장소 포트."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from phc.operations.domain.backup import BackupArtifact, BackupId

__all__ = ["BackupStorePort"]


class BackupStorePort(Protocol):
    def save(self, artifact: BackupArtifact) -> None: ...

    def get(self, backup_id: BackupId) -> BackupArtifact | None: ...

    def list_all(self) -> list[BackupArtifact]:
        """생성 시각 최신순."""
        ...

    def delete(self, backup_id: BackupId) -> None:
        """세대 정리 대상 삭제.

        ⚠ 감사 로그와 달리 백업 메타데이터는 삭제 가능합니다 — 보관 주기
        정책(BR-BK-04)이 요구하는 정상 동작이기 때문입니다.
        """
        ...

    def last_successful_at(self) -> datetime | None:
        """마지막 성공 백업 시각. 기동 시 미실행 보충 판정에 사용됩니다."""
        ...
