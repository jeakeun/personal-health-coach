"""MFA 등록·검증 (S22, F5=A)."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final

from phc.identity.domain.mfa import (
    RECOVERY_CODE_COUNT,
    RECOVERY_LOW_WATERMARK,
    MfaEnrollment,
    MfaRecoveryCode,
    RecoveryCodeId,
)
from phc.identity.ports.password import PasswordHasherPort
from phc.identity.ports.repositories import MfaRepositoryPort
from phc.identity.ports.totp import TotpPort
from phc.shared import CipherPort, CipherPurpose, ClockPort, DomainError, SecretStr, UserId

__all__ = ["EnrollmentChallenge", "MfaEnroller", "MfaVerificationResult", "RecoveryCodeBundle"]

#: 복구 코드 길이 (문자). base32 10자 ≈ 50비트.
_RECOVERY_CODE_BYTES: Final = 6


@dataclass(frozen=True, slots=True)
class EnrollmentChallenge:
    """등록 1단계 결과. 평문 비밀키는 **여기에만** 실립니다 (INV-MF-01)."""

    secret: SecretStr
    provisioning_uri: str


@dataclass(frozen=True, slots=True)
class RecoveryCodeBundle:
    """복구 코드 평문. **1회만** 표시되고 저장되지 않습니다 (INV-RC-01)."""

    codes: tuple[SecretStr, ...]


@dataclass(frozen=True, slots=True)
class MfaVerificationResult:
    ok: bool
    used_recovery_code: bool = False
    remaining_recovery_codes: int = 0

    @property
    def should_warn_low_codes(self) -> bool:
        return self.used_recovery_code and self.remaining_recovery_codes <= RECOVERY_LOW_WATERMARK


class MfaEnroller:
    def __init__(
        self,
        *,
        repository: MfaRepositoryPort,
        totp: TotpPort,
        cipher: CipherPort,
        hasher: PasswordHasherPort,
        clock: ClockPort,
    ) -> None:
        self._repository = repository
        self._totp = totp
        self._cipher = cipher
        self._hasher = hasher
        self._clock = clock

    # -- 등록 (2단계) ---------------------------------------------------------
    def begin_enrollment(self, user_id: UserId, account_name: str) -> EnrollmentChallenge:
        """1단계 — 비밀키 발급. 아직 MFA 는 활성화되지 않습니다 (INV-MF-02)."""
        secret = self._totp.generate_secret()
        enrollment = MfaEnrollment(
            user_id=user_id,
            secret_cipher=self._cipher.encrypt(secret.reveal().encode(), CipherPurpose.MFA_SECRET),
            enrolled_at=self._clock.now(),
        )
        self._repository.save_enrollment(enrollment)
        return EnrollmentChallenge(
            secret=secret,
            provisioning_uri=self._totp.provisioning_uri(secret, account_name),
        )

    def confirm_enrollment(self, user_id: UserId, code: str) -> RecoveryCodeBundle:
        """2단계 — 첫 코드 검증 성공 시 활성화하고 복구 코드를 발급한다.

        ⭐ 2단계를 두는 이유: 등록만 하고 확인하지 않은 상태에서 MFA 가
        활성화되면, 인증 앱에 제대로 등록되지 않은 채 계정에 갇힙니다.
        """
        enrollment = self._repository.get_enrollment(user_id)
        if enrollment is None:
            raise DomainError("mfa_not_enrolled", "MFA 등록을 먼저 시작해 주세요.")

        secret = self._decrypt_secret(enrollment)
        if not self._totp.verify(secret, code, now=self._clock.now()):
            raise DomainError("mfa_code_invalid", "코드가 올바르지 않습니다.")

        self._repository.save_enrollment(enrollment.confirm(now=self._clock.now()))
        return self._issue_recovery_codes(user_id)

    def disable(self, user_id: UserId) -> None:
        self._repository.delete_enrollment(user_id)
        self._repository.replace_recovery_codes(user_id, [])

    # -- 검증 ---------------------------------------------------------------
    def is_required(self, user_id: UserId) -> bool:
        enrollment = self._repository.get_enrollment(user_id)
        return enrollment is not None and enrollment.is_active

    def verify(self, user_id: UserId, code: str) -> MfaVerificationResult:
        """TOTP 또는 복구 코드로 검증한다.

        ⚠ 두 실패를 구분하지 않습니다 — 어느 쪽이 틀렸는지가 정보입니다.
        """
        enrollment = self._repository.get_enrollment(user_id)
        if enrollment is None or not enrollment.is_active:
            return MfaVerificationResult(ok=False)

        now = self._clock.now()
        secret = self._decrypt_secret(enrollment)

        if self._totp.verify(secret, code, now=now):
            return MfaVerificationResult(ok=True)

        return self._try_recovery_code(user_id, code, now=now)

    def _try_recovery_code(
        self, user_id: UserId, code: str, *, now: object
    ) -> MfaVerificationResult:
        candidate = SecretStr(code.strip().replace("-", "").upper())

        for stored in self._repository.list_recovery_codes(user_id):
            if not stored.is_available:
                continue
            if not self._hasher.verify(candidate, stored.code_hash):
                continue

            self._repository.update_recovery_code(stored.consume(now=self._clock.now()))
            remaining = sum(
                1 for c in self._repository.list_recovery_codes(user_id) if c.is_available
            )
            return MfaVerificationResult(
                ok=True, used_recovery_code=True, remaining_recovery_codes=remaining
            )

        return MfaVerificationResult(ok=False)

    # -- 복구 코드 -----------------------------------------------------------
    def reissue_recovery_codes(self, user_id: UserId) -> RecoveryCodeBundle:
        return self._issue_recovery_codes(user_id)

    def _issue_recovery_codes(self, user_id: UserId) -> RecoveryCodeBundle:
        now = self._clock.now()
        plain: list[SecretStr] = []
        stored: list[MfaRecoveryCode] = []

        for _ in range(RECOVERY_CODE_COUNT):
            raw = secrets.token_hex(_RECOVERY_CODE_BYTES).upper()
            plain.append(SecretStr(raw))
            stored.append(
                MfaRecoveryCode(
                    id=RecoveryCodeId.generate(),
                    user_id=user_id,
                    code_hash=self._hasher.hash(SecretStr(raw)),
                    created_at=now,
                )
            )

        self._repository.replace_recovery_codes(user_id, stored)
        return RecoveryCodeBundle(codes=tuple(plain))

    # -- 내부 ---------------------------------------------------------------
    def _decrypt_secret(self, enrollment: MfaEnrollment) -> SecretStr:
        return SecretStr(
            self._cipher.decrypt(enrollment.secret_cipher, CipherPurpose.MFA_SECRET).decode()
        )
