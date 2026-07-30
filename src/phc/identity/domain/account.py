"""계정 도메인 (S17).

불변식:
    INV-AC-01  평문·가역 형태 비밀번호를 담은 필드가 존재하지 않는다  🔬 속성 2
    INV-AC-02  username 은 정규화 결과 기준으로 전역 유일하다
    INV-AC-03  role==ADMIN 이면서 is_active 인 계정이 최소 1개 존재한다
    INV-AC-04  이 엔티티에 이메일 필드가 존재하지 않는다 (F1=A, NFR-34)
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from phc.shared import PasswordHash, Role, UserId, Username

__all__ = ["Account", "AccountSummary"]


@dataclass(frozen=True, slots=True)
class Account:
    """사용자 계정.

    ``password_hash`` 만 보유하며 평문 필드가 없습니다 (INV-AC-01).
    이메일 필드도 없습니다 — 쓰이지 않는 개인정보를 수집하지 않기 위함입니다
    (INV-AC-04).
    """

    id: UserId
    username: Username
    #: 원본 입력 표기. 판정은 ``username`` 으로, 표시는 이 값으로 합니다.
    display_name: str
    password_hash: PasswordHash
    role: Role
    is_active: bool
    must_change_password: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None

    # -- 판정 ---------------------------------------------------------------
    @property
    def can_sign_in(self) -> bool:
        return self.is_active

    @property
    def is_active_admin(self) -> bool:
        """INV-AC-03 판정에 사용."""
        return self.role is Role.ADMIN and self.is_active

    # -- 전이 ---------------------------------------------------------------
    def with_password(
        self, password_hash: PasswordHash, *, now: datetime, must_change: bool = False
    ) -> Account:
        return replace(
            self,
            password_hash=password_hash,
            must_change_password=must_change,
            updated_at=now,
        )

    def with_role(self, role: Role, *, now: datetime) -> Account:
        return replace(self, role=role, updated_at=now)

    def with_active(self, is_active: bool, *, now: datetime) -> Account:
        return replace(self, is_active=is_active, updated_at=now)

    def with_login(self, *, now: datetime) -> Account:
        return replace(self, last_login_at=now, updated_at=now)

    # -- 표현 ---------------------------------------------------------------
    def summary(self) -> AccountSummary:
        """관리자 콘솔에 노출되는 형태.

        ⭐ 건강 데이터 필드도, ``password_hash`` 도 담기지 않습니다
        (BR-AD-02, BR-AD-09).
        """
        return AccountSummary(
            id=self.id,
            username=self.username,
            display_name=self.display_name,
            role=self.role,
            is_active=self.is_active,
            last_login_at=self.last_login_at,
        )

    def __redacted_repr__(self) -> str:
        return f"Account(id={self.id}, role={self.role.value}, active={self.is_active})"


@dataclass(frozen=True, slots=True)
class AccountSummary:
    """관리자 콘솔 응답 모델.

    ⭐ **여기 없는 것이 중요합니다.** 건강 데이터 · 추천 · 대화 이력 · 비밀번호
    해시 어느 것도 이 타입에 존재하지 않습니다. 관리자 화면이 표현할 수 있는
    것의 상한이 이 타입입니다 (US-48).
    """

    id: UserId
    username: Username
    display_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None

    def __redacted_repr__(self) -> str:
        return f"AccountSummary(id={self.id}, role={self.role.value})"
