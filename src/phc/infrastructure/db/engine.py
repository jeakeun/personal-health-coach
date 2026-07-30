"""SQLite 엔진 구성 (S28, D-03).

⭐ **WAL 모드**를 켜는 이유:
   워커 스레드와 웹 요청이 동시에 DB 를 씁니다. 기본 저널 모드에서는 읽기가
   쓰기를 막아 로그인 응답이 백업 작업에 걸립니다. WAL 은 읽기와 쓰기를
   동시에 진행시킵니다.

⭐ ``busy_timeout`` 5초:
   쓰기는 여전히 직렬화되므로 짧은 경합이 생깁니다. 즉시 실패시키면 정상
   요청이 죽으므로 5초까지 기다립니다. 초과하면 ⛔ fail closed 로 거부합니다
   (BR-ER-01) — 무한 대기가 아닙니다.

⭐ ``foreign_keys=ON``:
   SQLite 는 기본으로 외래키를 **강제하지 않습니다**. 켜지 않으면 제약을
   선언해 두고도 검사되지 않는, 이 프로젝트가 반복해서 마주친 부류의
   상태가 됩니다 (F-05/06/07/17/18).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError

from phc.infrastructure.db.schema import METADATA
from phc.shared import DomainError, StartupError

__all__ = ["BUSY_TIMEOUT_MS", "Database", "create_sqlite_engine", "open_database"]

#: BR-ER-01 — 이 시간을 넘기면 대기하지 않고 거부합니다.
BUSY_TIMEOUT_MS: Final = 5_000

_GENERIC_DB_MESSAGE: Final = (
    "일시적인 문제로 요청을 처리할 수 없습니다. 잠시 후 다시 시도해 주세요."
)


def create_sqlite_engine(db_path: Path | str, *, echo: bool = False) -> Engine:
    """SQLite 엔진을 만들고 PRAGMA 를 적용한다.

    ``":memory:"`` 를 넘기면 인메모리 DB 를 만듭니다 (테스트용).
    """
    in_memory = str(db_path) == ":memory:"

    if isinstance(db_path, Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)

    url = f"sqlite:///{db_path}"
    engine = create_engine(url, echo=echo, future=True)

    @event.listens_for(engine, "connect")
    def _apply_pragmas(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            # 인메모리 DB 는 WAL 을 지원하지 않으므로 건너뜁니다.
            if not in_memory:
                cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            # 쓰기 내구성과 성능의 절충. FULL 은 매 커밋마다 fsync 하여 로컬
            # 데스크톱에 과도하고, OFF 는 전원 손실 시 손상 위험이 있습니다.
            # WAL + NORMAL 이 표준 조합입니다.
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

    return engine


class Database:
    """엔진과 트랜잭션 경계를 감싼다.

    트랜잭션 경계는 **서비스 메서드 단위**가 기본입니다 (BR-TX-01).
    명시된 예외는 둘입니다 — 스로틀 카운터는 별도 커밋(BR-TX-02),
    취입은 배치 커밋(1B).
    """

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @property
    def engine(self) -> Engine:
        return self._engine

    def create_all(self) -> None:
        """스키마를 생성한다 — **테스트·개발 전용**.

        ⚠ 운영 경로는 Alembic 마이그레이션입니다 (S30). 이 메서드로 만든 DB 는
        리비전 정보가 없어 ``BackupArtifact.schema_version`` 판정(BR-BK-07)이
        성립하지 않습니다.
        """
        METADATA.create_all(self._engine)

    @contextmanager
    def transaction(self) -> Iterator[Connection]:
        """트랜잭션 경계. 예외 발생 시 롤백합니다.

        ⛔ DB 오류를 ``DomainError`` 로 감쌉니다. 원본 예외를 그대로 흘리면
        SQL 문·파일 경로가 응답에 새어 나갈 수 있습니다 (NFR-1A-26).
        """
        try:
            with self._engine.begin() as connection:
                yield connection
        except SQLAlchemyError as exc:
            raise DomainError(
                "database_error", _GENERIC_DB_MESSAGE, detail=type(exc).__name__
            ) from exc

    @contextmanager
    def connect(self) -> Iterator[Connection]:
        """읽기 전용 연결. 커밋하지 않습니다."""
        try:
            with self._engine.connect() as connection:
                yield connection
        except SQLAlchemyError as exc:
            raise DomainError(
                "database_error", _GENERIC_DB_MESSAGE, detail=type(exc).__name__
            ) from exc

    def check_health(self) -> None:
        """깊은 헬스체크용 (L-09). 실패하면 예외를 던집니다."""
        with self.connect() as connection:
            connection.execute(text("SELECT 1"))

    def dispose(self) -> None:
        self._engine.dispose()


def open_database(db_path: Path, *, echo: bool = False) -> Database:
    """운영 기동 경로 (기동 시퀀스 4단계).

    ⛔ 열 수 없으면 ``StartupError`` — 기동을 중단합니다. 손상되었을지 모르는
    상태로 서비스하지 않습니다.
    """
    try:
        return Database(create_sqlite_engine(db_path, echo=echo))
    except (SQLAlchemyError, OSError) as exc:
        raise StartupError(
            "데이터베이스를 열 수 없습니다.",
            detail=f"path={db_path} error={type(exc).__name__}",
        ) from exc
