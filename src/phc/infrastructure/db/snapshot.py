"""DB 스냅샷 — ``SnapshotSource`` 의 SQLite 구현 (S30).

``operations.services.backup`` 의 ``SnapshotSource`` 프로토콜을 **구조적으로**
만족합니다. 프로토콜을 import 하지 않는 이유는 의존 방향입니다 —
``operations`` 가 ``infrastructure`` 를 쓰지, 그 반대가 아닙니다.

⭐ **SQLite 온라인 백업 API** 를 씁니다. 파일을 그대로 복사하면 워커가 쓰는
   도중의 상태가 잡혀 복원 불가능한 백업이 만들어집니다. 백업 API 는 쓰기와
   동시에 진행하면서도 일관된 사본을 만듭니다.

⭐ ``schema_version`` 은 **DB 에 적용된 Alembic 리비전**입니다 (BR-BK-07).
   앱 버전이 아니라 DB 버전이어야 합니다 — 백업은 그 시점 DB 의 사본이지
   그 시점 코드의 사본이 아닙니다.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from phc.infrastructure.db.engine import Database
from phc.infrastructure.db.migrations import current_revision
from phc.shared import DomainError

__all__ = ["SqliteSnapshotSource"]


class SqliteSnapshotSource:
    """백업·복원이 다루는 DB 스냅샷."""

    def __init__(self, database: Database, db_path: Path) -> None:
        self._db = database
        self._path = db_path

    @property
    def schema_version(self) -> str:
        """⛔ 리비전을 알 수 없으면 백업하지 않습니다.

        버전 없는 백업은 나중에 복원 가능 여부를 판정할 수 없습니다. 그 상태를
        만들어 두면 정작 복구가 필요한 순간에 "복원해도 되는지 모르는 파일"만
        남습니다. ``BackupRunner`` 가 이 예외를 잡아 감사·알림을 남깁니다.
        """
        revision = current_revision(self._db)
        if revision is None:
            raise DomainError(
                "schema_version_unknown",
                "데이터베이스 스키마 버전을 확인할 수 없어 백업할 수 없습니다.",
                detail="alembic_version 이 비어 있습니다 — 마이그레이션 미적용 DB",
            )
        return revision

    def create_snapshot(self) -> bytes:
        """일관된 DB 사본을 만든다 (BR-BK-02)."""
        with tempfile.TemporaryDirectory(prefix="phc-snapshot-") as workspace:
            target_path = Path(workspace) / "snapshot.db"
            raw = self._db.engine.raw_connection()
            try:
                source: Any = raw.driver_connection
                target = sqlite3.connect(str(target_path))
                try:
                    source.backup(target)
                finally:
                    target.close()
            finally:
                raw.close()
            return target_path.read_bytes()

    def restore_snapshot(self, data: bytes) -> None:
        """스냅샷으로 DB 파일을 교체한다 (US-38, 런북 R1).

        ⛔ 교체 후 **애플리케이션을 재기동해야 합니다.** 열려 있던 연결은 옛
           파일을 가리키고 있고, 그 상태로 계속 쓰면 복원한 내용이 다시 덮입니다.
           그래서 여기서 엔진을 닫습니다 — 재기동 없이 서비스가 이어지는 경로를
           남기지 않습니다.

        ⛔ 넘어온 바이트가 정상 SQLite DB 인지 먼저 확인합니다. 확인 전에
           원본을 지우면 되돌릴 수 없습니다.
        """
        with tempfile.TemporaryDirectory(prefix="phc-restore-") as workspace:
            staged = Path(workspace) / "restored.db"
            staged.write_bytes(data)
            self._assert_valid_sqlite(staged)

            self._db.dispose()

            # 원본을 지우기 전에 옆에 둡니다. 복사 중 실패해도 되돌릴 수 있습니다.
            rollback_copy = self._path.with_suffix(self._path.suffix + ".pre-restore")
            if self._path.exists():
                shutil.copy2(self._path, rollback_copy)

            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(staged, self._path)
            except OSError as exc:
                if rollback_copy.exists():
                    shutil.copy2(rollback_copy, self._path)
                raise DomainError(
                    "restore_failed",
                    "복원에 실패했습니다. 이전 데이터베이스를 그대로 두었습니다.",
                    detail=f"error={type(exc).__name__}",
                ) from exc

            # WAL·SHM 은 옛 DB 의 것입니다. 남겨 두면 복원한 파일과 짝이 맞지
            # 않아 손상으로 보입니다.
            for suffix in ("-wal", "-shm"):
                Path(str(self._path) + suffix).unlink(missing_ok=True)

    @staticmethod
    def _assert_valid_sqlite(path: Path) -> None:
        try:
            connection = sqlite3.connect(str(path))
            try:
                result = connection.execute("PRAGMA integrity_check").fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise DomainError(
                "backup_corrupt",
                "백업 파일을 열 수 없어 복원하지 않았습니다.",
                detail=f"error={type(exc).__name__}",
            ) from exc

        if result is None or result[0] != "ok":
            raise DomainError(
                "backup_corrupt",
                "백업 파일이 손상되어 복원하지 않았습니다.",
                detail=f"integrity_check={result[0] if result else 'none'}",
            )
