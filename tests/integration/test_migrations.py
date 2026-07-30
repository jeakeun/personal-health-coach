"""Alembic 마이그레이션 검증 (S30).

⭐ **이 파일의 핵심은 드리프트 검출입니다.**
   ``schema.py`` 와 ``0001_initial_schema.py`` 는 같은 스키마에 대한 두 개의
   진술입니다. 둘이 어긋나면 테스트는 인메모리·``create_all`` DB 로 통과하는데
   실제 운영 DB 만 다른 상태가 됩니다 — 이 프로젝트가 Phase 1·3 에서 반복해서
   마주친 "게이트가 걸려 있는데 실제로는 검사하지 않는" 부류(F-05/06/07/17/18)와
   같은 형태입니다. 그래서 두 경로로 DB 를 실제로 만들어 대조합니다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, inspect, text

from phc.infrastructure.db.engine import Database, create_sqlite_engine
from phc.infrastructure.db.migrations import (
    current_revision,
    head_revision,
    known_schema_order,
    upgrade_to_head,
)
from phc.infrastructure.db.schema import METADATA
from phc.infrastructure.db.snapshot import SqliteSnapshotSource
from phc.shared import DomainError

EXPECTED_TABLES = {
    "accounts",
    "alerts",
    "audit_archives",
    "audit_entries",
    "backup_artifacts",
    "jobs",
    "login_attempts",
    "mfa_enrollments",
    "mfa_recovery_codes",
    "sessions",
    "throttle_states",
}


def _migrated(tmp_path: Path) -> Database:
    database = Database(create_sqlite_engine(tmp_path / "migrated.db"))
    upgrade_to_head(database)
    return database


def _created(tmp_path: Path) -> Database:
    database = Database(create_sqlite_engine(tmp_path / "created.db"))
    database.create_all()
    return database


def _describe(engine: Engine) -> dict[str, dict[str, Any]]:
    """비교 가능한 형태로 스키마를 뽑는다."""
    inspector = inspect(engine)
    described: dict[str, dict[str, Any]] = {}
    for table in inspector.get_table_names():
        if table == "alembic_version":
            continue
        described[table] = {
            "columns": sorted(
                (column["name"], str(column["type"]), bool(column["nullable"]))
                for column in inspector.get_columns(table)
            ),
            "primary_key": sorted(inspector.get_pk_constraint(table)["constrained_columns"]),
            "indexes": sorted(
                (index["name"], tuple(index["column_names"]), bool(index.get("unique")))
                for index in inspector.get_indexes(table)
            ),
            "unique_constraints": sorted(
                tuple(constraint["column_names"])
                for constraint in inspector.get_unique_constraints(table)
            ),
        }
    return described


# ---------------------------------------------------------------------------
# 적용
# ---------------------------------------------------------------------------
def test_upgrade_creates_every_table(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        tables = set(inspect(database.engine).get_table_names())
        assert EXPECTED_TABLES <= tables
    finally:
        database.dispose()


def test_upgrade_stamps_head_revision(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        assert current_revision(database) == head_revision()
    finally:
        database.dispose()


def test_upgrade_is_idempotent(tmp_path: Path) -> None:
    """매 기동마다 호출되므로 두 번 돌려도 같아야 합니다."""
    database = _migrated(tmp_path)
    try:
        before = _describe(database.engine)
        assert upgrade_to_head(database) == head_revision()
        assert _describe(database.engine) == before
    finally:
        database.dispose()


def test_create_all_db_has_no_revision(tmp_path: Path) -> None:
    """⚠ ``create_all`` 로 만든 DB 는 리비전이 없습니다 — 백업 판정이 불가합니다."""
    database = _created(tmp_path)
    try:
        assert current_revision(database) is None
    finally:
        database.dispose()


# ---------------------------------------------------------------------------
# ⭐ 드리프트 검출
# ---------------------------------------------------------------------------
def test_migration_matches_schema_definition(tmp_path: Path) -> None:
    """마이그레이션이 만든 DB 와 ``METADATA.create_all()`` 이 만든 DB 가 같은가."""
    migrated = _migrated(tmp_path)
    created = _created(tmp_path)
    try:
        assert _describe(migrated.engine) == _describe(created.engine)
    finally:
        migrated.dispose()
        created.dispose()


def test_schema_module_and_expected_tables_agree() -> None:
    """``schema.py`` 가 테이블을 추가·삭제하면 이 테스트가 먼저 알려줍니다."""
    assert set(METADATA.tables) == EXPECTED_TABLES


# ---------------------------------------------------------------------------
# 되돌리기
# ---------------------------------------------------------------------------
def test_downgrade_removes_every_table(tmp_path: Path) -> None:
    from alembic import command

    from phc.infrastructure.db.migrations import alembic_config

    database = _migrated(tmp_path)
    try:
        config = alembic_config()
        with database.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "base")
        remaining = set(inspect(database.engine).get_table_names())
        assert not (EXPECTED_TABLES & remaining)
    finally:
        database.dispose()


# ---------------------------------------------------------------------------
# 백업 버전 연동 (BR-BK-07)
# ---------------------------------------------------------------------------
def test_known_schema_order_starts_at_base_and_ends_at_head() -> None:
    order = known_schema_order()
    assert order[0] == "0001"
    assert order[-1] == head_revision()
    assert len(set(order)) == len(order)


def test_snapshot_schema_version_is_the_applied_revision(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        source = SqliteSnapshotSource(database, tmp_path / "migrated.db")
        assert source.schema_version == head_revision()
    finally:
        database.dispose()


def test_snapshot_refuses_when_revision_unknown(tmp_path: Path) -> None:
    """⛔ 버전 없는 백업을 만들지 않습니다 — 나중에 복원 가능 여부를 판정할 수 없습니다."""
    database = _created(tmp_path)
    try:
        source = SqliteSnapshotSource(database, tmp_path / "created.db")
        with pytest.raises(DomainError) as caught:
            _ = source.schema_version
        assert caught.value.code == "schema_version_unknown"
    finally:
        database.dispose()


# ---------------------------------------------------------------------------
# 스냅샷 왕복
# ---------------------------------------------------------------------------
def test_snapshot_roundtrip_restores_earlier_state(tmp_path: Path) -> None:
    db_path = tmp_path / "migrated.db"
    database = _migrated(tmp_path)
    source = SqliteSnapshotSource(database, db_path)

    with database.transaction() as connection:
        connection.execute(
            text(
                "INSERT INTO audit_archives (id, covers_from, covers_to, seq_from,"
                " seq_to, artifact_ref, checksum, archived_at)"
                " VALUES ('a1', '2026-01-01', '2026-01-02', 1, 9, 'ref', 'sum', '2026-01-02')"
            )
        )

    snapshot = source.create_snapshot()

    # 스냅샷 이후의 변경 — 복원되면 사라져야 합니다.
    with database.transaction() as connection:
        connection.execute(text("DELETE FROM audit_archives"))
    with database.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM audit_archives")).scalar() == 0

    source.restore_snapshot(snapshot)

    # 복원은 엔진을 닫습니다 (재기동 전제). 확인은 새 연결로 합니다.
    reopened = Database(create_sqlite_engine(db_path))
    try:
        with reopened.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM audit_archives")).scalar() == 1
        assert current_revision(reopened) == head_revision()
    finally:
        reopened.dispose()


def test_restore_refuses_corrupt_snapshot(tmp_path: Path) -> None:
    """⛔ 검증 실패 시 원본을 건드리지 않습니다."""
    db_path = tmp_path / "migrated.db"
    database = _migrated(tmp_path)
    try:
        source = SqliteSnapshotSource(database, db_path)
        before = db_path.read_bytes()

        with pytest.raises(DomainError) as caught:
            source.restore_snapshot(b"this is not a sqlite database")

        assert caught.value.code == "backup_corrupt"
        assert db_path.read_bytes() == before
    finally:
        database.dispose()
