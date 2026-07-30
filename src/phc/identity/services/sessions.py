"""세션 관리 (S21, D6=A).

⭐ **캐시가 없습니다** (ND8=A).
   캐시 무효화가 한 번 실패하면 FR-35("로그아웃 시 즉시 무효화")가 깨지고,
   폐기된 세션으로 접근이 **조용히** 계속됩니다. NFR-1A-08(≤10ms)은 인덱싱된
   단일 행 조회로 이미 달성되므로, 성능 근거 없이 정합성 위험만 사는 거래입니다.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from phc.identity.domain.account import Account
from phc.identity.domain.session import (
    DEFAULT_ABSOLUTE_LIFETIME,
    DEFAULT_IDLE_LIFETIME,
    Session,
    hash_token,
)
from phc.identity.ports.repositories import SessionRepositoryPort
from phc.shared import (
    AuthContext,
    ClockPort,
    DomainError,
    SessionToken,
    UndeterminedError,
    UserId,
)

__all__ = ["IssuedSession", "SessionManager"]


class IssuedSession:
    """발급 결과. 토큰 원문은 여기에만 있고 저장소에는 해시만 남습니다."""

    __slots__ = ("session", "token")

    def __init__(self, token: SessionToken, session: Session) -> None:
        self.token = token
        self.session = session


class SessionManager:
    def __init__(
        self,
        *,
        repository: SessionRepositoryPort,
        clock: ClockPort,
        idle_lifetime: timedelta = DEFAULT_IDLE_LIFETIME,
        absolute_lifetime: timedelta = DEFAULT_ABSOLUTE_LIFETIME,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._idle_lifetime = idle_lifetime
        self._absolute_lifetime = absolute_lifetime

    # -- 발급 ---------------------------------------------------------------
    def issue(self, account: Account) -> IssuedSession:
        """새 세션 식별자를 발급한다 (BR-SE-09, 세션 고정 공격 방지)."""
        token = SessionToken.generate()
        session = Session.issue(
            token,
            account.id,
            now=self._clock.now(),
            idle_lifetime=self._idle_lifetime,
            absolute_lifetime=self._absolute_lifetime,
        )
        self._repository.put(session)
        return IssuedSession(token, session)

    # -- 검증 ---------------------------------------------------------------
    def resolve(self, token: SessionToken, account_lookup: object = None) -> Session | None:
        """세션을 해석한다. 유효하지 않으면 ``None``.

        ⛔ 저장소 조회가 실패하면 ``UndeterminedError`` 를 던집니다 —
        "조회를 못 했으니 통과" 가 아닙니다 (BR-SE-10).

        매 요청 호출됩니다 (BR-SE-04, NFR-48). 로그인 시점 검증으로
        갈음하지 않습니다.
        """
        now = self._clock.now()
        try:
            session = self._repository.get(hash_token(token))
        except DomainError:
            raise
        except Exception as exc:
            raise UndeterminedError(
                "session_store", detail=f"세션 조회 실패: {type(exc).__name__}"
            ) from exc

        if session is None or not session.is_valid(now):
            return None

        # 유휴 만료만 갱신합니다. 절대 만료는 밀지 않습니다 (INV-SE-02).
        touched = session.touch(now=now, idle_lifetime=self._idle_lifetime)
        self._repository.put(touched)
        return touched

    def to_context(self, session: Session, account: Account) -> AuthContext:
        return AuthContext(
            subject_id=account.id,
            role=account.role,
            must_change_password=account.must_change_password,
        )

    # -- 폐기 ---------------------------------------------------------------
    def revoke(self, token: SessionToken) -> None:
        """로그아웃 — 즉시 무효화 (FR-35, BR-SE-06). 지연 삭제가 아닙니다."""
        self._repository.delete(hash_token(token))

    def revoke_all_for(self, user_id: UserId) -> int:
        """비밀번호 변경 · 역할 변경 · 계정 비활성화 시 전량 무효화 (BR-SE-08)."""
        return self._repository.delete_by_user(user_id)

    # -- 유지보수 -----------------------------------------------------------
    def purge_expired(self) -> int:
        """만료 세션 정리.

        실패해도 인증 판정에 영향이 없습니다 — 판정은 시각 비교로 독립
        수행되기 때문입니다 (BR-SE-11).
        """
        return self._repository.purge_expired(self._clock.now())

    def active_count(self) -> int:
        return self._repository.count_active(self._clock.now())

    @property
    def idle_lifetime(self) -> timedelta:
        return self._idle_lifetime

    def expires_at(self, session: Session) -> datetime:
        return min(session.idle_expires_at, session.absolute_expires_at)
