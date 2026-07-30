"""Alembic 실행 환경 (S30, D-05).

⭐ **운영 스키마 경로는 여기 하나입니다.**
   ``Database.create_all()`` 은 테스트·개발 전용입니다. 그것으로 만든 DB 는
   ``alembic_version`` 이 비어 있어 백업의 ``schema_version`` 판정(BR-BK-07)이
   성립하지 않습니다 — 어떤 버전에서 만들어진 백업인지 알 수 없는 상태가 됩니다.

⭐ **DB 경로를 설정 파일에 고정하지 않는 이유**:
   실제 DB 는 ``%LOCALAPPDATA%\\PersonalHealthCoach\\data\\`` 에 있고(I2=B)
   사용자 계정마다 다릅니다. 해석 순서는 아래와 같습니다.

       1. ``config.attributes["connection"]``  — 앱 기동 경로 (엔진 재사용)
       2. ``alembic -x db=<경로>``             — 운영 스크립트·복구 런북 R1
       3. 환경변수 ``PHC_DB_PATH``             — 테스트·CI
       4. 기본 데이터 디렉터리

⚠ **``alembic.ini`` 에는 한글을 쓰지 않습니다.**
   configparser 가 로케일 인코딩(한국어 Windows 에서 cp949)으로 읽어
   ``UnicodeDecodeError`` 로 죽습니다. F-06 에서 ``.importlinter`` 를
   ``pyproject.toml`` 로 옮긴 것과 같은 이유이며, S30 작업 중 실제로 다시
   발생했습니다(F-20). 설명은 UTF-8 인 이 파일에 둡니다.

⭐ ``render_as_batch=True``:
   SQLite 는 ``ALTER TABLE`` 로 컬럼을 바꾸거나 지우지 못합니다. 배치 모드가
   임시 테이블을 만들어 복사하는 방식으로 우회합니다. 1A 에서는 초기 생성뿐이라
   쓰이지 않지만, 1B 이후 스키마 확장에서 이 설정이 없으면 마이그레이션을
   작성할 수 없게 됩니다.
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic import context
from sqlalchemy import Connection

from phc.infrastructure.db.engine import create_sqlite_engine
from phc.infrastructure.db.schema import METADATA

config = context.config
target_metadata = METADATA


def _default_db_path() -> Path:
    """기본 데이터 디렉터리 (I2=B). 저장소 밖입니다."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    root = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return root / "PersonalHealthCoach" / "data" / "phc.db"


def _resolve_db_path() -> Path:
    x_args = context.get_x_argument(as_dictionary=True)
    raw = x_args.get("db") or os.environ.get("PHC_DB_PATH")
    return Path(raw) if raw else _default_db_path()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        # 타입 변경을 자동 감지 대상에 포함합니다. 없으면 String(32) -> String(64)
        # 같은 변경이 autogenerate 에서 조용히 누락됩니다.
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """SQL 스크립트만 출력한다 (``alembic upgrade head --sql``).

    운영자가 적용 전에 무엇이 실행되는지 확인하는 경로입니다 (런북 R1).
    """
    context.configure(
        url=f"sqlite:///{_resolve_db_path()}",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # 앱 기동 경로는 이미 열린 연결을 넘깁니다. 새 엔진을 만들면 PRAGMA
    # (WAL·foreign_keys·busy_timeout)가 적용되지 않은 연결로 스키마를 바꾸게
    # 됩니다.
    injected = config.attributes.get("connection")
    if injected is not None:
        _run(injected)
        return

    engine = create_sqlite_engine(_resolve_db_path())
    try:
        with engine.begin() as connection:
            _run(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
