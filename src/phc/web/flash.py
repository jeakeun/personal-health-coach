"""플래시 메시지 (S32, D-02.1).

POST → 리다이렉트 → GET 패턴에서 결과 문구를 다음 화면으로 넘깁니다.
쿠키에 담고 **표시 즉시 삭제**합니다.

⚠ 담기는 것은 화면에 그대로 보여도 되는 문구뿐입니다. 임시 비밀번호·TOTP
   비밀키 같은 1회 표시 값은 여기 넣지 않습니다 — 쿠키는 디스크에 남습니다.
   그런 값은 POST 응답에서 **직접 렌더링**합니다 (`OneTimeSecretPanel`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from urllib.parse import quote, unquote

from fastapi import Request, Response

from phc.web.deps import COOKIE_FLASH

__all__ = ["FlashMessage", "clear", "read", "set_flash"]

#: 쿠키 길이 상한. 넘치면 브라우저가 조용히 버립니다.
MAX_MESSAGE_LENGTH: Final = 200

_LEVELS: Final[frozenset[str]] = frozenset({"success", "error"})


@dataclass(frozen=True, slots=True)
class FlashMessage:
    level: str
    text: str

    @property
    def is_error(self) -> bool:
        return self.level == "error"


def set_flash(response: Response, level: str, text: str, *, secure: bool = False) -> None:
    if level not in _LEVELS:  # pragma: no cover - 호출자 오류 방어
        raise ValueError(f"알 수 없는 플래시 등급: {level}")
    payload = f"{level}|{quote(text[:MAX_MESSAGE_LENGTH])}"
    response.set_cookie(
        COOKIE_FLASH,
        payload,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def read(request: Request) -> FlashMessage | None:
    """쿠키에서 메시지를 해석한다. 삭제는 `clear` 가 합니다."""
    raw = request.cookies.get(COOKIE_FLASH)
    if not raw or "|" not in raw:
        return None

    level, _, encoded = raw.partition("|")
    if level not in _LEVELS:
        return None
    return FlashMessage(level=level, text=unquote(encoded)[:MAX_MESSAGE_LENGTH])


def clear(response: Response) -> None:
    """표시한 메시지를 지운다. 같은 메시지가 두 번 보이지 않습니다."""
    response.delete_cookie(COOKIE_FLASH, path="/")
