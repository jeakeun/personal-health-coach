"""Alembic 연동 (S30, D-05).

⭐ **리비전이 곧 ``BackupArtifact.schema_version`` 입니다** (BR-BK-07).
   1A 의 백업은 ``"0001"``, 1B 에서 건강 데이터 테이블이 붙으면 ``"0002"`` 가
   됩니다. ``known_schema_order()`` 가 base→head 순서를 주고,
   ``BackupArtifact.is_restorable_onto`` 가 그 순서로 전후를 판정합니다.

   순서를 손으로 적은 상수로 두지 않는 이유: 리비전을 추가하면서 상수 갱신을
   잊으면 **정상 백업이 조용히 "복원 불가"로 판정**됩니다. 실제로 필요할 때—
   즉 복구 중—에 드러나는 종류의 오류입니다. 그래서 스크립트 디렉터리에서
   직접 읽습니다.

⛔ 스키마 적용에 실패하면 ``StartupError`` 로 기동을 중단합니다.
   어떤 스키마인지 모르는 DB 로 서비스하지 않습니다 (BR-ER-05).
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy.exc import SQLAlchemyError

from phc.infrastructure.db.engine import Database
from phc.shared import StartupError

__all__ = [
    "alembic_config",
    "current_revision",
    "head_revision",
    "known_schema_order",
    "upgrade_to_head",
]


@cache
def _alembic_root() -> Path:
    """``alembic.ini`` 와 ``migrations/`` 가 있는 디렉터리를 찾는다.

    경로를 상수로 박지 않고 탐색하는 이유: 설치 형태(editable / 소스 실행)에
    따라 모듈 파일 위치와 프로젝트 루트의 상대 관계가 달라집니다.
    """
    module_path = Path(__file__).resolve()
    candidates = [*module_path.parents[2:6], Path.cwd()]
    for candidate in candidates:
        if (candidate / "alembic.ini").is_file() and (
            candidate / "migrations" / "env.py"
        ).is_file():
            return candidate
    raise StartupError(
        "마이그레이션 설정을 찾을 수 없습니다.",
        detail=f"탐색 경로: {[str(c) for c in candidates]}",
    )


def alembic_config() -> Config:
    """프로그램 경로용 Alembic 설정.

    DB 위치는 여기서 정하지 않습니다 — ``upgrade_to_head`` 가 이미 열린 연결을
    주입하므로, 새 엔진이 PRAGMA 없이 만들어지는 경로가 생기지 않습니다.
    """
    root = _alembic_root()
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    return config


def head_revision() -> str:
    """현재 코드가 기대하는 스키마 버전."""
    script = ScriptDirectory.from_config(alembic_config())
    head = script.get_current_head()
    if head is None:
        raise StartupError(
            "마이그레이션 리비전이 하나도 없습니다.",
            detail=f"script_location={script.dir}",
        )
    return head


def known_schema_order() -> list[str]:
    """base → head 순서의 리비전 목록 (BR-BK-07 판정용)."""
    script = ScriptDirectory.from_config(alembic_config())
    return [revision.revision for revision in reversed(list(script.walk_revisions()))]


def current_revision(database: Database) -> str | None:
    """DB 에 실제로 적용된 스키마 버전.

    ``None`` 이면 마이그레이션이 한 번도 적용되지 않은 DB 입니다 —
    ``Database.create_all()`` 로 만든 테스트용 DB 가 여기 해당합니다.
    """
    with database.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def upgrade_to_head(database: Database) -> str:
    """스키마를 최신 리비전까지 올린다 (기동 시퀀스).

    이미 최신이면 아무것도 하지 않습니다 — 매 기동마다 호출해도 안전합니다.
    """
    config = alembic_config()
    try:
        with database.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
    except (SQLAlchemyError, CommandError, OSError) as exc:
        raise StartupError(
            "데이터베이스 스키마를 적용할 수 없습니다.",
            detail=f"error={type(exc).__name__}",
        ) from exc
    return head_revision()
