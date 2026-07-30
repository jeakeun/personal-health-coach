"""공유 커널 — 도메인 오류 계층.

핵심 설계: **사용자에게 보여줄 문구와 내부 로그용 상세를 분리 보유**합니다
(BR-ER-03). 이 분리가 없으면 개발자가 편의상 예외 메시지를 그대로 응답에
실어 내부 경로 · 스택 · 프레임워크 정보가 새어 나갑니다 (NFR-08).

fail closed 원칙:
    판정에 필요한 정보를 얻을 수 없을 때는 ``UNDETERMINED`` 로 판정하고
    호출자가 **차단**으로 처리합니다. "확실하지 않으면 통과"를 하는 경로가
    이 코드베이스에 없습니다 (NFR-09).
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AuthzError",
    "ConflictError",
    "DomainError",
    "PolicyViolationError",
    "SafetyVerdict",
    "StartupError",
    "UndeterminedError",
    "ValidationError",
]


class SafetyVerdict(StrEnum):
    """3값 판정.

    ⚠ ``UNDETERMINED`` 는 **차단으로 처리**됩니다. 2값(통과/차단)으로 두면
    "판정 불가"가 어느 쪽으로든 흘러갈 수 있고, 실무에서는 통과 쪽으로 흐릅니다.
    3값으로 두면 호출자가 명시적으로 처리해야 합니다.
    """

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNDETERMINED = "undetermined"

    @property
    def passes(self) -> bool:
        """통과 여부. ``UNDETERMINED`` 는 통과가 아닙니다."""
        return self is SafetyVerdict.ALLOWED


class DomainError(Exception):
    """도메인 오류의 기반 클래스.

    Args:
        code: 기계 판독용 코드. 로그·감사에 기록됩니다.
        safe_message: **사용자에게 그대로 보여도 되는** 문구.
            내부 구조를 드러내지 않아야 합니다.
        detail: 내부 로그 전용 상세. 응답에 실리지 않습니다.
    """

    def __init__(self, code: str, safe_message: str, *, detail: str | None = None) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message
        self.detail = detail

    def __redacted_repr__(self) -> str:
        """로그용 표현. ``detail`` 은 포함하되 사용자 입력값은 담지 않습니다."""
        return f"{type(self).__name__}(code={self.code})"


class ValidationError(DomainError):
    """입력 형식·길이·범위 위반."""

    def __init__(self, safe_message: str, *, field: str | None = None) -> None:
        super().__init__("validation_failed", safe_message, detail=f"field={field}")
        self.field = field


class PolicyViolationError(DomainError):
    """정책 위반 — 비밀번호 정책, 예약어, 관리자 0명 방지 등."""

    def __init__(self, code: str, safe_message: str, *, detail: str | None = None) -> None:
        super().__init__(code, safe_message, detail=detail)


class ConflictError(DomainError):
    """중복·경쟁 상태.

    ⚠ 사용자명 중복의 ``safe_message`` 는 기존 계정의 존재 여부를 과도하게
    노출하지 않는 문구여야 합니다 (BR-SU-03).
    """

    def __init__(self, code: str, safe_message: str, *, detail: str | None = None) -> None:
        super().__init__(code, safe_message, detail=detail)


class AuthzError(DomainError):
    """인가 거부.

    ⚠ 이 오류가 발생하면 **예외 없이 감사 기록**됩니다 (BR-AZ-07).
    ``AUTHZ_DENIED`` 이벤트가 US-48 의 인수 기준("거부가 감사 로그에 기록된다")을
    직접 담당합니다.
    """

    def __init__(
        self,
        safe_message: str = "접근 권한이 없습니다.",
        *,
        detail: str | None = None,
    ) -> None:
        super().__init__("authz_denied", safe_message, detail=detail)


class UndeterminedError(DomainError):
    """⛔ fail closed — 판정에 필요한 정보를 얻지 못했다.

    이 예외를 잡아서 "일단 진행" 하는 코드를 작성해서는 안 됩니다.
    발생 지점은 6곳입니다 (business-rules.md §14):

    - 유출 비밀번호 목록 조회 실패      -> 가입·변경 거부
    - 스로틀 상태 조회 실패             -> 로그인 거부
    - 세션 저장소 조회 실패             -> 요청 거부
    - 인가 정보 취득 실패               -> 접근 거부
    - 키 저장소 접근 실패               -> 기동 중단 (``StartupError``)
    - 백업 검증 실패                    -> 복원 거부
    """

    def __init__(self, what: str, *, detail: str | None = None) -> None:
        super().__init__(
            "undetermined",
            "일시적인 문제로 요청을 처리할 수 없습니다. 잠시 후 다시 시도해 주세요.",
            detail=f"undetermined:{what} {detail or ''}".strip(),
        )
        self.what = what


class StartupError(DomainError):
    """⛔ 기동 중단 — 안전하게 시작할 수 없는 상태.

    대표 사례는 암호화 키 저장소 접근 실패입니다 (BR-ER-05).
    **암호화 없이 건강 데이터를 기록하는 경로를 만들지 않기 위해**,
    이 경우 서비스를 시작하지 않고 종료합니다.
    """

    def __init__(self, safe_message: str, *, detail: str | None = None) -> None:
        super().__init__("startup_failed", safe_message, detail=detail)
