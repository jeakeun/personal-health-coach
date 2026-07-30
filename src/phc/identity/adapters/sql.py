"""identity SQL 어댑터 (S28, D-04 SQLAlchemy Core).

⚠ 도메인 객체 ↔ 행 매핑을 **손으로** 합니다. ORM 을 쓰면 도메인 모델이
   SQLAlchemy 클래스에 종속되어 인메모리 구현으로 대체할 수 없게 되고,
   그것이 곧 NFR-1A-38 판정 실패입니다.

⭐ 이 어댑터들은 인메모리 구현과 **같은 계약 테스트**를 통과해야 합니다
   (S29). 두 구현이 같은 명세를 만족한다는 것이 포트 추상화의 실질입니다.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Row, delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from phc.identity.domain.account import Account
from phc.identity.domain.mfa import MfaEnrollment, MfaRecoveryCode, RecoveryCodeId
from phc.identity.domain.session import Session
from phc.identity.domain.throttle import (
    AttemptOutcome,
    LoginAttempt,
    ThrottleKey,
    ThrottleState,
)
from phc.infrastructure.db.engine import Database
from phc.infrastructure.db.schema import (
    accounts,
    login_attempts,
    mfa_enrollments,
    mfa_recovery_codes,
    sessions,
    throttle_states,
)
from phc.shared import ConflictError, PasswordHash, Role, UserId, Username

__all__ = [
    "SqlAccountRepository",
    "SqlMfaRepository",
    "SqlSessionRepository",
    "SqlThrottleRepository",
]


def _aware(value: datetime | None) -> datetime | None:
    """SQLite 는 timezone 을 잃어버리므로 UTC 로 되살립니다.

    ⚠ 이것을 하지 않으면 naive 와 aware 를 비교하다 ``TypeError`` 가 납니다.
    세션 만료·잠금 판정이 전부 시각 비교이므로 조용히 넘어갈 수 없습니다.
    """
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _required(value: datetime | None) -> datetime:
    aware = _aware(value)
    if aware is None:
        raise ValueError("필수 시각 컬럼이 비어 있습니다.")
    return aware


# ---------------------------------------------------------------------------
# 계정
# ---------------------------------------------------------------------------
class SqlAccountRepository:
    def __init__(self, database: Database) -> None:
        self._db = database

    @staticmethod
    def _to_domain(row: Row[Any]) -> Account:
        return Account(
            id=UserId(row.id),
            username=Username(row.username),
            display_name=row.display_name,
            password_hash=PasswordHash(row.password_hash),
            role=Role(row.role),
            is_active=bool(row.is_active),
            must_change_password=bool(row.must_change_password),
            created_at=_required(row.created_at),
            updated_at=_required(row.updated_at),
            last_login_at=_aware(row.last_login_at),
        )

    def find_by_username(self, username: Username) -> Account | None:
        with self._db.connect() as conn:
            row = conn.execute(
                select(accounts).where(accounts.c.username == username.normalized)
            ).one_or_none()
        return self._to_domain(row) if row is not None else None

    def find_by_id(self, user_id: UserId) -> Account | None:
        with self._db.connect() as conn:
            row = conn.execute(select(accounts).where(accounts.c.id == user_id.value)).one_or_none()
        return self._to_domain(row) if row is not None else None

    def save(self, account: Account) -> None:
        values = {
            "id": account.id.value,
            "username": account.username.normalized,
            "display_name": account.display_name,
            "password_hash": account.password_hash.encoded,
            "role": account.role.value,
            "is_active": account.is_active,
            "must_change_password": account.must_change_password,
            "created_at": account.created_at,
            "updated_at": account.updated_at,
            "last_login_at": account.last_login_at,
        }
        try:
            with self._db.transaction() as conn:
                existing = conn.execute(
                    select(accounts.c.id).where(accounts.c.id == account.id.value)
                ).one_or_none()
                if existing is None:
                    conn.execute(insert(accounts).values(**values))
                else:
                    conn.execute(
                        update(accounts).where(accounts.c.id == account.id.value).values(**values)
                    )
        except Exception as exc:
            # ⭐ 유일 제약 위반이 INV-AC-02 의 **최종 방어**입니다.
            #    사전 조회만으로는 동시 가입 경쟁을 막을 수 없습니다.
            if isinstance(exc.__cause__, IntegrityError) or isinstance(exc, IntegrityError):
                raise ConflictError(
                    "username_taken",
                    "해당 사용자명으로는 가입할 수 없습니다.",
                    detail=f"username={account.username.normalized}",
                ) from exc
            raise

    def list_all(self) -> list[Account]:
        with self._db.connect() as conn:
            rows = conn.execute(select(accounts).order_by(accounts.c.created_at)).all()
        return [self._to_domain(row) for row in rows]

    def count_active_admins(self) -> int:
        with self._db.connect() as conn:
            result = conn.execute(
                select(func.count())
                .select_from(accounts)
                .where(accounts.c.role == Role.ADMIN.value, accounts.c.is_active.is_(True))
            ).scalar_one()
        return int(result)


# ---------------------------------------------------------------------------
# 세션
# ---------------------------------------------------------------------------
class SqlSessionRepository:
    def __init__(self, database: Database) -> None:
        self._db = database

    @staticmethod
    def _to_domain(row: Row[Any]) -> Session:
        return Session(
            token_hash=row.token_hash,
            user_id=UserId(row.user_id),
            issued_at=_required(row.issued_at),
            last_seen_at=_required(row.last_seen_at),
            idle_expires_at=_required(row.idle_expires_at),
            absolute_expires_at=_required(row.absolute_expires_at),
            revoked_at=_aware(row.revoked_at),
        )

    def put(self, session: Session) -> None:
        values = {
            "token_hash": session.token_hash,
            "user_id": session.user_id.value,
            "issued_at": session.issued_at,
            "last_seen_at": session.last_seen_at,
            "idle_expires_at": session.idle_expires_at,
            "absolute_expires_at": session.absolute_expires_at,
            "revoked_at": session.revoked_at,
        }
        with self._db.transaction() as conn:
            existing = conn.execute(
                select(sessions.c.token_hash).where(sessions.c.token_hash == session.token_hash)
            ).one_or_none()
            if existing is None:
                conn.execute(insert(sessions).values(**values))
            else:
                conn.execute(
                    update(sessions)
                    .where(sessions.c.token_hash == session.token_hash)
                    .values(**values)
                )

    def get(self, token_hash: str) -> Session | None:
        with self._db.connect() as conn:
            row = conn.execute(
                select(sessions).where(sessions.c.token_hash == token_hash)
            ).one_or_none()
        return self._to_domain(row) if row is not None else None

    def delete(self, token_hash: str) -> None:
        with self._db.transaction() as conn:
            conn.execute(delete(sessions).where(sessions.c.token_hash == token_hash))

    def delete_by_user(self, user_id: UserId) -> int:
        with self._db.transaction() as conn:
            result = conn.execute(delete(sessions).where(sessions.c.user_id == user_id.value))
        return int(result.rowcount or 0)

    def purge_expired(self, now: datetime) -> int:
        """만료·폐기 세션을 지운다.

        ⚠ 판정은 애플리케이션에서 다시 하므로(BR-SE-11), 여기서 조금 덜
        지워도 인증 정합성에는 영향이 없습니다.
        """
        with self._db.transaction() as conn:
            result = conn.execute(
                delete(sessions).where(
                    (sessions.c.absolute_expires_at <= now)
                    | (sessions.c.idle_expires_at <= now)
                    | (sessions.c.revoked_at.is_not(None))
                )
            )
        return int(result.rowcount or 0)

    def count_active(self, now: datetime) -> int:
        with self._db.connect() as conn:
            result = conn.execute(
                select(func.count())
                .select_from(sessions)
                .where(
                    sessions.c.absolute_expires_at > now,
                    sessions.c.idle_expires_at > now,
                    sessions.c.revoked_at.is_(None),
                )
            ).scalar_one()
        return int(result)


# ---------------------------------------------------------------------------
# 스로틀
# ---------------------------------------------------------------------------
class SqlThrottleRepository:
    """⚠ 이 저장소의 쓰기는 **인증 트랜잭션과 분리**되어야 합니다 (BR-TX-02).

    인증 실패로 롤백되면 실패 카운터도 되돌아가 방어가 무력화됩니다.
    각 메서드가 자기 트랜잭션을 열고 즉시 커밋하는 이유입니다.
    """

    def __init__(self, database: Database) -> None:
        self._db = database

    def get_state(self, key: ThrottleKey) -> ThrottleState | None:
        with self._db.connect() as conn:
            row = conn.execute(
                select(throttle_states).where(
                    throttle_states.c.username_normalized == key.username_normalized,
                    throttle_states.c.client_key == key.client_key,
                )
            ).one_or_none()

        if row is None:
            return None

        return ThrottleState(
            key=key,
            consecutive_failures=row.consecutive_failures,
            first_failure_at=_aware(row.first_failure_at),
            last_failure_at=_aware(row.last_failure_at),
            locked_until=_aware(row.locked_until),
        )

    def save_state(self, state: ThrottleState) -> None:
        values = {
            "username_normalized": state.key.username_normalized,
            "client_key": state.key.client_key,
            "consecutive_failures": state.consecutive_failures,
            "first_failure_at": state.first_failure_at,
            "last_failure_at": state.last_failure_at,
            "locked_until": state.locked_until,
        }
        with self._db.transaction() as conn:
            existing = conn.execute(
                select(throttle_states.c.username_normalized).where(
                    throttle_states.c.username_normalized == state.key.username_normalized,
                    throttle_states.c.client_key == state.key.client_key,
                )
            ).one_or_none()
            if existing is None:
                conn.execute(insert(throttle_states).values(**values))
            else:
                conn.execute(
                    update(throttle_states)
                    .where(
                        throttle_states.c.username_normalized == state.key.username_normalized,
                        throttle_states.c.client_key == state.key.client_key,
                    )
                    .values(**values)
                )

    def record_attempt(self, attempt: LoginAttempt) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                insert(login_attempts).values(
                    username_normalized=attempt.username_normalized,
                    client_key=attempt.client_key,
                    occurred_at=attempt.occurred_at,
                    outcome=attempt.outcome.value,
                )
            )

    def count_failures_since(self, username_normalized: str, since: datetime) -> int:
        with self._db.connect() as conn:
            result = conn.execute(
                select(func.count())
                .select_from(login_attempts)
                .where(
                    login_attempts.c.username_normalized == username_normalized,
                    login_attempts.c.occurred_at >= since,
                    login_attempts.c.outcome != AttemptOutcome.SUCCESS.value,
                )
            ).scalar_one()
        return int(result)

    def count_all_failures_since(self, since: datetime) -> int:
        with self._db.connect() as conn:
            result = conn.execute(
                select(func.count())
                .select_from(login_attempts)
                .where(
                    login_attempts.c.occurred_at >= since,
                    login_attempts.c.outcome != AttemptOutcome.SUCCESS.value,
                )
            ).scalar_one()
        return int(result)


# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------
class SqlMfaRepository:
    def __init__(self, database: Database) -> None:
        self._db = database

    def get_enrollment(self, user_id: UserId) -> MfaEnrollment | None:
        with self._db.connect() as conn:
            row = conn.execute(
                select(mfa_enrollments).where(mfa_enrollments.c.user_id == user_id.value)
            ).one_or_none()

        if row is None:
            return None

        return MfaEnrollment(
            user_id=UserId(row.user_id),
            secret_cipher=row.secret_cipher,
            enrolled_at=_required(row.enrolled_at),
            confirmed_at=_aware(row.confirmed_at),
        )

    def save_enrollment(self, enrollment: MfaEnrollment) -> None:
        values = {
            "user_id": enrollment.user_id.value,
            "secret_cipher": enrollment.secret_cipher,
            "enrolled_at": enrollment.enrolled_at,
            "confirmed_at": enrollment.confirmed_at,
        }
        with self._db.transaction() as conn:
            existing = conn.execute(
                select(mfa_enrollments.c.user_id).where(
                    mfa_enrollments.c.user_id == enrollment.user_id.value
                )
            ).one_or_none()
            if existing is None:
                conn.execute(insert(mfa_enrollments).values(**values))
            else:
                conn.execute(
                    update(mfa_enrollments)
                    .where(mfa_enrollments.c.user_id == enrollment.user_id.value)
                    .values(**values)
                )

    def delete_enrollment(self, user_id: UserId) -> None:
        with self._db.transaction() as conn:
            conn.execute(delete(mfa_enrollments).where(mfa_enrollments.c.user_id == user_id.value))

    def list_recovery_codes(self, user_id: UserId) -> list[MfaRecoveryCode]:
        with self._db.connect() as conn:
            rows = conn.execute(
                select(mfa_recovery_codes)
                .where(mfa_recovery_codes.c.user_id == user_id.value)
                .order_by(mfa_recovery_codes.c.created_at)
            ).all()

        return [
            MfaRecoveryCode(
                id=RecoveryCodeId(row.id),
                user_id=UserId(row.user_id),
                code_hash=PasswordHash(row.code_hash),
                created_at=_required(row.created_at),
                used_at=_aware(row.used_at),
            )
            for row in rows
        ]

    def save_recovery_codes(self, codes: list[MfaRecoveryCode]) -> None:
        if not codes:
            return
        with self._db.transaction() as conn:
            conn.execute(
                insert(mfa_recovery_codes),
                [
                    {
                        "id": code.id.value,
                        "user_id": code.user_id.value,
                        "code_hash": code.code_hash.encoded,
                        "created_at": code.created_at,
                        "used_at": code.used_at,
                    }
                    for code in codes
                ],
            )

    def update_recovery_code(self, code: MfaRecoveryCode) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                update(mfa_recovery_codes)
                .where(mfa_recovery_codes.c.id == code.id.value)
                .values(used_at=code.used_at)
            )

    def replace_recovery_codes(self, user_id: UserId, codes: list[MfaRecoveryCode]) -> None:
        """재발급 — 기존 코드를 전부 폐기하고 새로 만든다.

        삭제와 삽입이 **한 트랜잭션**이어야 합니다. 중간에 끊기면 복구 코드가
        하나도 없는 상태가 남습니다.
        """
        with self._db.transaction() as conn:
            conn.execute(
                delete(mfa_recovery_codes).where(mfa_recovery_codes.c.user_id == user_id.value)
            )
            if codes:
                conn.execute(
                    insert(mfa_recovery_codes),
                    [
                        {
                            "id": code.id.value,
                            "user_id": code.user_id.value,
                            "code_hash": code.code_hash.encoded,
                            "created_at": code.created_at,
                            "used_at": code.used_at,
                        }
                        for code in codes
                    ],
                )
