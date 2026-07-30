"""세션 도메인 (S17).

불변식:
    INV-SE-01  유효한 세션 = 미폐기 AND 유휴 미만료 AND 절대 미만료
    INV-SE-02  절대 만료는 갱신되지 않는다. 활동이 있어도 유휴 만료만 밀린다
    INV-SE-03  저장소에는 토큰 해시만 있다. 원문을 복원할 수 없다
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from phc.shared import SessionToken, UserId

__all__ = [
    "DEFAULT_ABSOLUTE_LIFETIME",
    "DEFAULT_IDLE_LIFETIME",
    "Session",
    "SessionInvalidReason",
    "hash_token",
]

#: F3=B — 유휴 60분 / 절대 7일
DEFAULT_IDLE_LIFETIME: Final = timedelta(minutes=60)
DEFAULT_ABSOLUTE_LIFETIME: Final = timedelta(days=7)


def hash_token(token: SessionToken) -> str:
    """토큰 원문을 저장용 해시로 변환한다.

    비밀번호와 달리 적응형 해시가 아니라 SHA-256 을 씁니다. 토큰은 128비트
    이상 엔트로피의 난수라 사전 공격 대상이 아니고, **매 요청 검증**되므로
    비용이 낮아야 합니다 (NFR-1A-08, 10ms 예산).
    """
    return hashlib.sha256(token.value.encode()).hexdigest()


class SessionInvalidReason(StrEnum):
    NOT_FOUND = "not_found"
    REVOKED = "revoked"
    IDLE_EXPIRED = "idle_expired"
    ABSOLUTE_EXPIRED = "absolute_expired"

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Session:
    """서버 측 세션 (D6=A).

    토큰 원문은 발급 직후 쿠키로 나가는 경로에만 존재하고, 여기에는
    해시만 남습니다 (INV-SE-03).
    """

    token_hash: str
    user_id: UserId
    issued_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None = None

    @classmethod
    def issue(
        cls,
        token: SessionToken,
        user_id: UserId,
        *,
        now: datetime,
        idle_lifetime: timedelta = DEFAULT_IDLE_LIFETIME,
        absolute_lifetime: timedelta = DEFAULT_ABSOLUTE_LIFETIME,
    ) -> Session:
        return cls(
            token_hash=hash_token(token),
            user_id=user_id,
            issued_at=now,
            last_seen_at=now,
            idle_expires_at=now + idle_lifetime,
            absolute_expires_at=now + absolute_lifetime,
        )

    # -- 판정 ---------------------------------------------------------------
    def invalid_reason(self, now: datetime) -> SessionInvalidReason | None:
        """무효 사유. 유효하면 ``None``.

        ⚠ 사유는 **내부 판정용**입니다. 사용자 응답에는 노출하지 않습니다 —
        어느 조건으로 끊겼는지가 정보가 됩니다.
        """
        if self.revoked_at is not None:
            return SessionInvalidReason.REVOKED
        if now >= self.absolute_expires_at:
            return SessionInvalidReason.ABSOLUTE_EXPIRED
        if now >= self.idle_expires_at:
            return SessionInvalidReason.IDLE_EXPIRED
        return None

    def is_valid(self, now: datetime) -> bool:
        return self.invalid_reason(now) is None

    # -- 전이 ---------------------------------------------------------------
    def touch(self, *, now: datetime, idle_lifetime: timedelta = DEFAULT_IDLE_LIFETIME) -> Session:
        """활동을 기록한다.

        ⭐ ``absolute_expires_at`` 은 **갱신하지 않습니다** (INV-SE-02).
        갱신하면 활동만 계속되면 세션이 영원히 살아 있게 되어, 절대 만료를
        둔 의미가 사라집니다.
        """
        return replace(self, last_seen_at=now, idle_expires_at=now + idle_lifetime)

    def revoke(self, *, now: datetime) -> Session:
        return replace(self, revoked_at=now)

    def __redacted_repr__(self) -> str:
        return f"Session(user={self.user_id}, issued={self.issued_at.isoformat()})"
