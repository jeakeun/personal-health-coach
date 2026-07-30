"""비밀번호 정책 (S19, NFR-41).

정책: 최소 8자 + 로컬 유출 목록 대조

⛔ 유출 목록을 읽을 수 없으면 ``UNDETERMINED`` 로 판정하고 **거부**합니다
   (BR-PW-03). "목록을 못 읽었으니 통과" 는 없는 선택지입니다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from phc.identity.ports.breach_list import BreachedPasswordListPort
from phc.shared import SafetyVerdict, SecretStr

__all__ = ["MIN_PASSWORD_LENGTH", "PasswordPolicy", "PolicyResult"]

MIN_PASSWORD_LENGTH: Final = 8

#: 상한을 두는 이유는 정책이 아니라 자원 보호입니다. 매우 긴 입력을
#: Argon2id 에 넣으면 해시 시간이 예산을 넘습니다.
MAX_PASSWORD_LENGTH: Final = 1024


@dataclass(frozen=True, slots=True)
class PolicyResult:
    verdict: SafetyVerdict
    reason_code: str | None = None
    message: str | None = None

    @property
    def passes(self) -> bool:
        return self.verdict.passes


class PasswordPolicy:
    def __init__(self, *, breach_list: BreachedPasswordListPort) -> None:
        self._breach_list = breach_list

    def validate(self, password: SecretStr) -> PolicyResult:
        """정책 검사. 3값을 반환합니다.

        ⚠ 반환값이 bool 이 아닌 이유: "판정 불가" 를 "통과" 로 흘릴 수
        없게 하기 위함입니다.
        """
        if len(password) < MIN_PASSWORD_LENGTH:
            return PolicyResult(
                SafetyVerdict.BLOCKED,
                "too_short",
                f"비밀번호는 {MIN_PASSWORD_LENGTH}자 이상이어야 합니다.",
            )

        if len(password) > MAX_PASSWORD_LENGTH:
            return PolicyResult(
                SafetyVerdict.BLOCKED,
                "too_long",
                f"비밀번호는 {MAX_PASSWORD_LENGTH}자를 넘을 수 없습니다.",
            )

        try:
            breached = self._breach_list.contains(password)
        except Exception:
            # ⛔ 판정 불가 — 호출자가 거부해야 합니다 (BR-PW-03).
            return PolicyResult(
                SafetyVerdict.UNDETERMINED,
                "breach_list_unavailable",
                "일시적인 문제로 비밀번호를 확인할 수 없습니다. 잠시 후 다시 시도해 주세요.",
            )

        if breached:
            return PolicyResult(
                SafetyVerdict.BLOCKED,
                "breached",
                "널리 유출된 비밀번호입니다. 다른 비밀번호를 사용해 주세요.",
            )

        return PolicyResult(SafetyVerdict.ALLOWED)
