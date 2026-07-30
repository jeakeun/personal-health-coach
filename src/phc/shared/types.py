"""공유 커널 — 값 타입.

이 모듈의 타입들은 **원시 문자열과 구별되는 별개 타입**입니다.
암묵 변환을 허용하지 않는 것이 이 유닛 안전 장치의 상당 부분을 지탱합니다.

규칙 문서에 "하지 마시오"라고 적는 것과, 타입이 그것을 불가능하게 만드는 것은
다릅니다. 후자만 실수에 견딥니다.

⚠ 이 모듈은 ``sqlalchemy`` · ``fastapi`` 를 import 하지 않습니다 (계약 C4).
"""

from __future__ import annotations

import secrets
import unicodedata
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

__all__ = [
    "MAX_USERNAME_LENGTH",
    "MIN_USERNAME_LENGTH",
    "RESERVED_USERNAMES",
    "AuthContext",
    "PasswordHash",
    "Redactable",
    "Role",
    "SecretStr",
    "SessionToken",
    "SupportsRedactedRepr",
    "UserId",
    "Username",
]


# ---------------------------------------------------------------------------
# Redactable — 로그·감사에 실릴 수 있는 값
# ---------------------------------------------------------------------------
@runtime_checkable
class SupportsRedactedRepr(Protocol):
    """로그용 안전 표현을 제공하는 도메인 타입."""

    def __redacted_repr__(self) -> str:
        """로그에 남길 안전한 표현."""
        ...


#: 로그 · 감사 기록에 담아도 되는 값.
#:
#: 원시 값(문자열 · 숫자 · 불리언 · None)과, 안전 표현을 스스로 제공하는
#: 도메인 타입만 허용합니다.
#:
#: ``SecretStr`` · ``PasswordHash`` · ``SessionToken`` 은 **어느 쪽에도
#: 해당하지 않습니다** — 원시 타입의 하위 클래스가 아니고
#: ``__redacted_repr__`` 도 정의하지 않습니다. 따라서 로그 함수의 인자로
#: 전달하면 타입 검사에서 걸립니다 (NFR-04, BR-AU-02).
#:
#: ⚠ 원시 문자열은 통과하므로 ``password="plain"`` 같은 호출은 타입 검사를
#:    빠져나갑니다. 그 경로는 ``RedactionProcessor`` 가 **키 이름**으로
#:    런타임 차단합니다. 정적 검사와 런타임 검사를 겹치는 이유입니다.
Redactable = SupportsRedactedRepr | str | int | float | bool | None


# ---------------------------------------------------------------------------
# SecretStr — 평문 비밀을 담는 래퍼
# ---------------------------------------------------------------------------
class SecretStr:
    """평문 비밀번호 · 임시 비밀번호 · TOTP 비밀키를 담는 래퍼.

    ``str()`` · ``repr()`` · f-string · 로그 포맷 어디에서도 값이 노출되지
    않습니다. 값을 꺼내려면 ``reveal()`` 을 **명시적으로** 호출해야 하며,
    이 호출이 코드 리뷰에서 눈에 띄는 것이 목적입니다.

    ``Redactable`` 을 만족하지 않으므로 로그 인자로 쓸 수 없습니다.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """평문을 꺼낸다. 호출 지점이 최소가 되도록 유지할 것."""
        return self._value

    def __str__(self) -> str:  # pragma: no cover - 사소하나 노출 방지에 필수
        return "SecretStr(***)"

    def __repr__(self) -> str:  # pragma: no cover
        return "SecretStr(***)"

    def __format__(self, format_spec: str) -> str:  # pragma: no cover
        return "SecretStr(***)"

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        # 상수 시간 비교. 비밀 값끼리의 비교가 타이밍 정보를 흘리지 않게 한다.
        if not isinstance(other, SecretStr):
            return NotImplemented
        return secrets.compare_digest(self._value, other._value)

    def __hash__(self) -> int:  # pragma: no cover
        # 해시 값으로 원문을 역산할 수 없게, 값이 아니라 정체성 기반으로 둔다.
        return id(self)


# ---------------------------------------------------------------------------
# PasswordHash — 적응형 해시 결과
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PasswordHash:
    """적응형 해시 결과. 알고리즘 식별자 · 파라미터 · 솔트를 포함한 인코딩 문자열.

    평문(``SecretStr``)과 타입이 다르므로 서로 섞이지 않습니다.
    ``Redactable`` 을 만족하지 않아 로그 경로에 진입할 수 없습니다 (NFR-40).
    """

    encoded: str

    def __str__(self) -> str:  # pragma: no cover
        return "PasswordHash(***)"

    def __repr__(self) -> str:  # pragma: no cover
        return "PasswordHash(***)"


# ---------------------------------------------------------------------------
# SessionToken — 클라이언트가 보유하는 토큰 원문
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class SessionToken:
    """세션 토큰 원문.

    ⚠ **저장소에는 이 값을 저장하지 않습니다.** 저장되는 것은 해시뿐입니다
    (INV-SE-03). 이 타입은 발급 직후 쿠키로 나가는 경로에만 존재합니다.
    """

    value: str

    @classmethod
    def generate(cls) -> SessionToken:
        """암호학적 난수로 토큰을 생성한다 (엔트로피 >= 128비트, NFR-1A-17)."""
        return cls(secrets.token_urlsafe(32))

    def __str__(self) -> str:  # pragma: no cover
        return "SessionToken(***)"

    def __repr__(self) -> str:  # pragma: no cover
        return "SessionToken(***)"


# ---------------------------------------------------------------------------
# UserId — 불투명 식별자
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True, order=True)
class UserId:
    """계정 식별자.

    추측 불가능한 불투명 값입니다. 순번을 노출하면 IDOR 시도 표면이
    넓어집니다 (NFR-46).
    """

    value: str

    @classmethod
    def generate(cls) -> UserId:
        return cls(uuid.uuid4().hex)

    def __str__(self) -> str:
        return self.value

    def __redacted_repr__(self) -> str:
        """식별자는 로그에 남겨도 됩니다 — 그 자체로 건강 데이터가 아닙니다."""
        return self.value


# ---------------------------------------------------------------------------
# Username — 정규화된 사용자명
# ---------------------------------------------------------------------------
MIN_USERNAME_LENGTH: Final = 3
MAX_USERNAME_LENGTH: Final = 32

#: 일반 회원가입에서 선점할 수 없는 사용자명 (BR-BS-10).
#: 자유 가입(F7=A)이므로, 부트스트랩 전에 누군가 ``admin`` 으로 가입하면
#: 관리자 부트스트랩(BR-BS-03)이 실패합니다.
RESERVED_USERNAMES: Final[frozenset[str]] = frozenset({"admin", "administrator", "root", "system"})

_ALLOWED_EXTRA: Final = frozenset({".", "_", "-"})


@dataclass(frozen=True, slots=True)
class Username:
    """정규화된 사용자명.

    **판정과 조회는 정규화 값으로, 화면 표시는 원본으로** 합니다.
    이 분리가 ``Admin`` 과 ``admin`` 이 서로 다른 계정이 되는 사고를 막습니다
    (INV-AC-02).
    """

    normalized: str

    @staticmethod
    def normalize(raw: str) -> str:
        """앞뒤 공백 제거 -> NFKC 정규화 -> 소문자 변환."""
        return unicodedata.normalize("NFKC", raw.strip()).casefold()

    @classmethod
    def parse(cls, raw: str) -> Username:
        """원본 입력을 검증하고 정규화한다.

        Raises:
            ValueError: 길이 또는 허용 문자 위반. 호출자가
                ``DomainError`` 로 변환하여 사용자에게 안내합니다.
        """
        normalized = cls.normalize(raw)

        if not (MIN_USERNAME_LENGTH <= len(normalized) <= MAX_USERNAME_LENGTH):
            raise ValueError(
                f"사용자명은 {MIN_USERNAME_LENGTH}~{MAX_USERNAME_LENGTH}자여야 합니다."
            )

        for ch in normalized:
            if not (ch.isalnum() or ch in _ALLOWED_EXTRA):
                raise ValueError("사용자명에는 영문자·숫자와 . _ - 만 사용할 수 있습니다.")

        return cls(normalized)

    def is_reserved(self) -> bool:
        return self.normalized in RESERVED_USERNAMES

    def __str__(self) -> str:
        return self.normalized

    def __redacted_repr__(self) -> str:
        return self.normalized


# ---------------------------------------------------------------------------
# Role
# ---------------------------------------------------------------------------
class Role(StrEnum):
    """계정 역할.

    ⚠ 관리자 역할의 추가 권한은 **계정 도메인 리소스에만** 적용됩니다.
    건강 데이터 · 추천 · 대화 이력에는 적용되지 않습니다 (FR-39, BR-AZ-04).
    """

    USER = "user"
    ADMIN = "admin"

    def __redacted_repr__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# AuthContext — 요청 스코프 불변 객체
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class AuthContext:
    """인증된 주체의 요청 스코프 컨텍스트.

    불변입니다. 요청 처리 중간에 주체가 바뀌지 않습니다.

    ⚠ 이 객체를 가지고 있다는 것은 **인증**되었다는 뜻일 뿐,
    특정 리소스에 대한 **인가**를 뜻하지 않습니다. 건강 데이터 접근에는
    ``OwnerScope`` 가 별도로 필요합니다 (경계 B).
    """

    subject_id: UserId
    role: Role
    must_change_password: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN

    def __redacted_repr__(self) -> str:
        return f"AuthContext(subject={self.subject_id}, role={self.role.value})"
