"""identity 인메모리 어댑터 (S18).

⭐ NFR-1A-38 의 판정 기준 — "인메모리 리포지토리 구현으로 도메인 테스트가
   통과하는가". Phase 4 에서 SQL 어댑터를 만든 뒤 **같은 계약 테스트를 두
   구현에 모두** 적용합니다 (S29).
"""

from __future__ import annotations

import threading
from datetime import datetime

from phc.identity.domain.account import Account
from phc.identity.domain.mfa import MfaEnrollment, MfaRecoveryCode, RecoveryCodeId
from phc.identity.domain.session import Session
from phc.identity.domain.throttle import AttemptOutcome, LoginAttempt, ThrottleKey, ThrottleState
from phc.shared import ConflictError, UserId, Username

__all__ = [
    "InMemoryAccountRepository",
    "InMemoryMfaRepository",
    "InMemorySessionRepository",
    "InMemoryThrottleRepository",
]


class InMemoryAccountRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[UserId, Account] = {}
        self._username_index: dict[str, UserId] = {}

    def find_by_username(self, username: Username) -> Account | None:
        with self._lock:
            user_id = self._username_index.get(username.normalized)
            return self._by_id.get(user_id) if user_id is not None else None

    def find_by_id(self, user_id: UserId) -> Account | None:
        with self._lock:
            return self._by_id.get(user_id)

    def save(self, account: Account) -> None:
        with self._lock:
            owner = self._username_index.get(account.username.normalized)
            # 유일 제약 — 사전 조회만으로는 동시 가입 경쟁을 막을 수 없습니다.
            if owner is not None and owner != account.id:
                raise ConflictError(
                    "username_taken",
                    "해당 사용자명으로는 가입할 수 없습니다.",
                    detail=f"username={account.username.normalized}",
                )
            self._by_id[account.id] = account
            self._username_index[account.username.normalized] = account.id

    def list_all(self) -> list[Account]:
        with self._lock:
            return sorted(self._by_id.values(), key=lambda a: a.created_at)

    def count_active_admins(self) -> int:
        with self._lock:
            return sum(1 for a in self._by_id.values() if a.is_active_admin)


class InMemorySessionRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    def put(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.token_hash] = session

    def get(self, token_hash: str) -> Session | None:
        with self._lock:
            return self._sessions.get(token_hash)

    def delete(self, token_hash: str) -> None:
        with self._lock:
            self._sessions.pop(token_hash, None)

    def delete_by_user(self, user_id: UserId) -> int:
        with self._lock:
            targets = [h for h, s in self._sessions.items() if s.user_id == user_id]
            for token_hash in targets:
                del self._sessions[token_hash]
            return len(targets)

    def purge_expired(self, now: datetime) -> int:
        with self._lock:
            expired = [h for h, s in self._sessions.items() if not s.is_valid(now)]
            for token_hash in expired:
                del self._sessions[token_hash]
            return len(expired)

    def count_active(self, now: datetime) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.is_valid(now))


class InMemoryThrottleRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[ThrottleKey, ThrottleState] = {}
        self._attempts: list[LoginAttempt] = []

    def get_state(self, key: ThrottleKey) -> ThrottleState | None:
        with self._lock:
            return self._states.get(key)

    def save_state(self, state: ThrottleState) -> None:
        with self._lock:
            self._states[state.key] = state

    def record_attempt(self, attempt: LoginAttempt) -> None:
        with self._lock:
            self._attempts.append(attempt)

    def count_failures_since(self, username_normalized: str, since: datetime) -> int:
        with self._lock:
            return sum(
                1
                for a in self._attempts
                if a.username_normalized == username_normalized
                and a.occurred_at >= since
                and a.outcome is not AttemptOutcome.SUCCESS
            )

    def count_all_failures_since(self, since: datetime) -> int:
        with self._lock:
            return sum(
                1
                for a in self._attempts
                if a.occurred_at >= since and a.outcome is not AttemptOutcome.SUCCESS
            )


class InMemoryMfaRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._enrollments: dict[UserId, MfaEnrollment] = {}
        self._codes: dict[RecoveryCodeId, MfaRecoveryCode] = {}

    def get_enrollment(self, user_id: UserId) -> MfaEnrollment | None:
        with self._lock:
            return self._enrollments.get(user_id)

    def save_enrollment(self, enrollment: MfaEnrollment) -> None:
        with self._lock:
            self._enrollments[enrollment.user_id] = enrollment

    def delete_enrollment(self, user_id: UserId) -> None:
        with self._lock:
            self._enrollments.pop(user_id, None)

    def list_recovery_codes(self, user_id: UserId) -> list[MfaRecoveryCode]:
        with self._lock:
            return [c for c in self._codes.values() if c.user_id == user_id]

    def save_recovery_codes(self, codes: list[MfaRecoveryCode]) -> None:
        with self._lock:
            for code in codes:
                self._codes[code.id] = code

    def update_recovery_code(self, code: MfaRecoveryCode) -> None:
        with self._lock:
            self._codes[code.id] = code

    def replace_recovery_codes(self, user_id: UserId, codes: list[MfaRecoveryCode]) -> None:
        with self._lock:
            for code_id in [c.id for c in self._codes.values() if c.user_id == user_id]:
                del self._codes[code_id]
            for code in codes:
                self._codes[code.id] = code
