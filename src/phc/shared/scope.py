"""공유 커널 — ``OwnerScope``. ⭐ 경계 B 의 핵심.

요구: FR-39 · FR-42 · NFR-46 · NFR-47 · US-42 · US-48 · RSK-10

경계 B 는 세 겹으로 보장됩니다. 이 모듈은 그중 **두 번째 겹**입니다.

1. 의존 방향 차단 — ``identity`` 가 ``healthdata`` · ``advisory`` 를 참조하지 않음
   (``.importlinter`` 계약 C2)
2. **API 표면에 우회 인자 부재** — 건강 데이터 접근에 ``OwnerScope`` 필수,
   그리고 ``OwnerScope`` 는 **인증된 주체로부터만** 만들 수 있음  ← 이 모듈
3. 역할 무관 불변식 — ``require_owner`` 가 ``ctx.role`` 을 읽지 않음
   (``phc.identity.services.authorization``)

핵심은 ``OwnerScope`` 를 **임의의 ``UserId`` 로 만들 수 없다**는 것입니다.
만들려면 ``AuthContext`` 가 필요하고, ``AuthContext`` 는 인증을 통과해야만
발급됩니다. 그래서 "관리자니까 다른 사용자 것도 조회" 를 **표현할 문법이
존재하지 않습니다**.

⚠ 이 보장의 범위:
    경계 B 는 **애플리케이션을 통한 접근**에 적용됩니다. 모든 사용자의 데이터가
    하나의 DB 파일에 있으므로, 그 파일에 OS 수준으로 접근할 수 있는 사람은
    타인의 데이터를 열람할 수 있습니다. 즉 US-48 은 앱 경로에 한정된 보장입니다.
    (Infrastructure Design §7)
"""

from __future__ import annotations

from typing import Final

from phc.shared.types import AuthContext, UserId

__all__ = ["OwnerScope"]


#: 생성 경로를 하나로 묶어 두기 위한 내부 열쇠.
#: 외부에서 ``OwnerScope(user_id)`` 를 직접 호출하면 이 열쇠가 없어 실패합니다.
_CONSTRUCTION_KEY: Final = object()


class OwnerScope:
    """건강 데이터 접근의 필수 인자.

    **공개 생성자가 없습니다.** 유일한 생성 경로는 :meth:`for_subject` 이며,
    이 메서드는 ``UserId`` 가 아니라 ``AuthContext`` 를 받습니다. 남의
    ``UserId`` 를 알고 있어도 그 사람의 스코프를 만들 수 없습니다.

    사용 예::

        scope = OwnerScope.for_subject(ctx)          # 인증 주체로부터
        measurements = repo.series(scope, metric, period)

    이 타입을 필수 인자로 요구하는 리포지토리에는 ``as_admin`` ·
    ``override_owner`` · ``include_all_users`` 같은 인자가 **존재하지 않습니다**.
    """

    __slots__ = ("_owner_id",)

    def __init__(self, owner_id: UserId, *, construction_key: object = None) -> None:
        if construction_key is not _CONSTRUCTION_KEY:
            raise TypeError(
                "OwnerScope 는 직접 생성할 수 없습니다. "
                "OwnerScope.for_subject(auth_context) 를 사용하십시오. "
                "이 제약이 경계 B(FR-39, US-48)를 타입 수준에서 강제합니다."
            )
        self._owner_id = owner_id

    # -- 유일한 생성 경로 ---------------------------------------------------
    @classmethod
    def for_subject(cls, ctx: AuthContext) -> OwnerScope:
        """인증된 주체 자신에 대한 스코프를 발급한다.

        ``ctx.role`` 을 **읽지 않습니다**. 관리자든 일반 사용자든 자기 자신의
        스코프만 얻습니다.
        """
        return cls(ctx.subject_id, construction_key=_CONSTRUCTION_KEY)

    # -- 읽기 전용 접근자 ---------------------------------------------------
    @property
    def owner_id(self) -> UserId:
        return self._owner_id

    # -- 값 의미론 ----------------------------------------------------------
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OwnerScope):
            return NotImplemented
        return self._owner_id == other._owner_id

    def __hash__(self) -> int:
        return hash(("OwnerScope", self._owner_id))

    def __repr__(self) -> str:
        return f"OwnerScope(owner_id={self._owner_id})"

    def __redacted_repr__(self) -> str:
        """소유자 식별자는 로그에 남겨도 됩니다 — 건강 데이터가 아닙니다."""
        return f"OwnerScope({self._owner_id})"
