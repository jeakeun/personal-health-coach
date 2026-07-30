"""폼 입력 처리 (S32 · 체인 6번 `RequestValidator`).

⭐ **클라이언트 검증은 편의일 뿐입니다.** 여기서 형식을 한 번 거르고, 정책
   판정은 다시 도메인 서비스가 합니다. 클라이언트 검증을 통과했다는 이유로
   서버 검증을 생략하는 경로가 없습니다 (NFR-05, NFR-47).

이 계층이 하는 일은 좁습니다 — **길이 상한과 존재 여부**입니다. 사용자명 규칙은
`Username.parse`, 비밀번호 규칙은 `PasswordPolicy` 가 판정합니다. 규칙을 두 곳에
쓰면 한쪽만 고쳐지는 날이 옵니다.
"""

from __future__ import annotations

from typing import Final

from starlette.datastructures import FormData

from phc.shared import SecretStr, ValidationError

__all__ = ["MAX_FIELD_LENGTH", "next_path", "optional_text", "required_secret", "required_text"]

#: 입력 길이 상한. 도메인 규칙이 아니라 자원 보호 장치입니다 —
#: 메가바이트짜리 사용자명이 적응형 해시까지 도달하지 않게 합니다.
MAX_FIELD_LENGTH: Final = 512


def optional_text(form: FormData, name: str) -> str:
    """폼 값을 문자열로 꺼낸다. 없으면 빈 문자열."""
    value = form.get(name)
    if not isinstance(value, str):
        return ""
    return value.strip()[:MAX_FIELD_LENGTH]


def required_text(form: FormData, name: str, *, label: str) -> str:
    value = optional_text(form, name)
    if not value:
        raise ValidationError(f"{label}을(를) 입력해 주세요.", field=name)
    return value


def required_secret(form: FormData, name: str, *, label: str) -> SecretStr:
    """비밀번호류. ⚠ 여기서부터 값은 `SecretStr` 로만 다뤄집니다.

    평문 ``str`` 로 들고 다니면 로그·오류 메시지에 섞여 들어갈 경로가 생깁니다.
    """
    raw = form.get(name)
    if not isinstance(raw, str) or not raw:
        raise ValidationError(f"{label}을(를) 입력해 주세요.", field=name)
    return SecretStr(raw[:MAX_FIELD_LENGTH])


def next_path(raw: str | None) -> str | None:
    """로그인 후 복귀 경로를 검증한다.

    ⛔ **오픈 리다이렉트 방어.** 앱 내부의 절대 경로만 허용합니다.
    ``//evil.example`` 는 브라우저가 스킴 상대 URL 로 해석하므로 거부합니다.
    """
    if not raw or not raw.startswith("/") or raw.startswith("//"):
        return None
    if len(raw) > MAX_FIELD_LENGTH or "\\" in raw:
        return None
    return raw
