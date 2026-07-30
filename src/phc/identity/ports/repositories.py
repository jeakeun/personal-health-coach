"""계정 도메인 리포지토리 포트 (D7=A).

⚠ **`OwnerScope` 를 받지 않습니다.** 관리자가 계정 목록을 보고 역할을
   바꾸는 것은 정당한 기능이므로, 계정 도메인에는 소유 범위 제약을 걸지
   않습니다.

   경계 B 는 "관리자가 계정을 관리하지 못하게" 하는 것이 아니라
   **"관리자 권한이 건강 데이터에 닿지 않게"** 하는 것입니다. 그 제약은
   1B 이후의 건강 데이터 리포지토리에 `OwnerScope` 필수 인자로 나타납니다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from phc.identity.domain.account import Account
from phc.identity.domain.mfa import MfaEnrollment, MfaRecoveryCode
from phc.identity.domain.session import Session
from phc.identity.domain.throttle import LoginAttempt, ThrottleKey, ThrottleState
from phc.shared import UserId, Username

__all__ = [
    "AccountRepositoryPort",
    "MfaRepositoryPort",
    "SessionRepositoryPort",
    "ThrottleRepositoryPort",
]


class AccountRepositoryPort(Protocol):
    def find_by_username(self, username: Username) -> Account | None: ...

    def find_by_id(self, user_id: UserId) -> Account | None: ...

    def save(self, account: Account) -> None:
        """계정을 저장한다.

        Raises:
            ConflictError: 사용자명이 이미 존재하는 경우 (INV-AC-02).
                저장소 유일 제약이 최종 방어입니다 — 사전 조회만으로는
                동시 가입 경쟁을 막을 수 없습니다.
        """
        ...

    def list_all(self) -> list[Account]: ...

    def count_active_admins(self) -> int:
        """INV-AC-03 판정에 사용. 관리자 0명이 되는 변경을 막습니다."""
        ...


class SessionRepositoryPort(Protocol):
    def put(self, session: Session) -> None: ...

    def get(self, token_hash: str) -> Session | None: ...

    def delete(self, token_hash: str) -> None: ...

    def delete_by_user(self, user_id: UserId) -> int:
        """해당 사용자의 모든 세션을 무효화한다.

        비밀번호 변경 · 역할 변경 · 계정 비활성화 시 호출됩니다 (BR-SE-08).
        """
        ...

    def purge_expired(self, now: datetime) -> int:
        """만료 세션 정리.

        ⚠ 정리 실패가 인증 판정에 영향을 주지 않아야 합니다. 판정은 시각
        비교로 독립 수행됩니다 (BR-SE-11).
        """
        ...

    def count_active(self, now: datetime) -> int:
        """메트릭용."""
        ...


class ThrottleRepositoryPort(Protocol):
    def get_state(self, key: ThrottleKey) -> ThrottleState | None:
        """Raises:
        DomainError: 조회 실패. ⛔ 호출자는 로그인을 **거부**해야 합니다
            (BR-TH-06). 스로틀 상태를 모르는 채 통과시키면 방어가 없습니다.
        """
        ...

    def save_state(self, state: ThrottleState) -> None:
        """⚠ 인증 트랜잭션과 **별도로 커밋**됩니다 (BR-TX-02).

        인증 실패로 롤백되면 실패 카운터도 되돌아가 방어가 무력화됩니다.
        """
        ...

    def record_attempt(self, attempt: LoginAttempt) -> None: ...

    def count_failures_since(self, username_normalized: str, since: datetime) -> int:
        """누적 알림 임계 판정에 사용 (동일 계정 10분 10회)."""
        ...

    def count_all_failures_since(self, since: datetime) -> int:
        """전체 로그인 실패 누적 (10분 30회)."""
        ...


class MfaRepositoryPort(Protocol):
    def get_enrollment(self, user_id: UserId) -> MfaEnrollment | None: ...

    def save_enrollment(self, enrollment: MfaEnrollment) -> None: ...

    def delete_enrollment(self, user_id: UserId) -> None: ...

    def list_recovery_codes(self, user_id: UserId) -> list[MfaRecoveryCode]: ...

    def save_recovery_codes(self, codes: list[MfaRecoveryCode]) -> None: ...

    def update_recovery_code(self, code: MfaRecoveryCode) -> None: ...

    def replace_recovery_codes(self, user_id: UserId, codes: list[MfaRecoveryCode]) -> None:
        """재발급 — 기존 코드를 전부 폐기하고 새로 만듭니다."""
        ...
