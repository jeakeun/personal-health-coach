"""관리자 부트스트랩 (S24) — ⭐ US-46 · FR-37 · RSK-11.

**멱등**입니다. 활성 관리자가 이미 있으면 아무것도 변경하지 않습니다.
재기동해도 비밀번호가 재설정되거나 계정이 중복 생성되지 않습니다 (BR-BS-02).

🔬 PBT 속성 1: ``bootstrap(bootstrap(s))`` 의 계정 집합 == ``bootstrap(s)``

⭐ 임시 비밀번호가 갈 수 없는 곳 (AC-17, BR-BS-05):

    StructuredLogger  — SecretStr 이 Redactable 이 아니라 인자로 전달 불가
    AuditTrail        — detail 타입이 Redactable
    설정 파일         — 쓰기 코드 경로 없음
    백업 아티팩트     — 해시만 저장되므로 백업에도 해시만
    HTTP 응답         — 웹 서버 시작 **전에** 실행됨

    ``BootstrapOutcome.console_notice`` 는 호출자가 콘솔에 1회 출력한 뒤
    폐기합니다. 그 외 경로가 코드에 존재하지 않습니다.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final

from phc.identity.domain.account import Account
from phc.identity.ports.password import PasswordHasherPort
from phc.identity.ports.repositories import AccountRepositoryPort
from phc.operations.domain.audit import AuditEntry, AuditEventType, AuditOutcome
from phc.operations.ports.audit import AuditTrailPort
from phc.shared import ClockPort, ConflictError, Role, SecretStr, UserId, Username

__all__ = ["BOOTSTRAP_USERNAME", "AdminBootstrapper", "BootstrapOutcome"]

#: F4=A — 고정 사용자명. 금지 대상은 **비밀번호**이지 사용자명이 아닙니다
#: (NFR-45). 로컬 루프백 실행이라 사용자명 열거 표면도 사실상 없습니다.
BOOTSTRAP_USERNAME: Final = "admin"

#: 임시 비밀번호 엔트로피 >= 96비트 (NFR-1A-18). token_urlsafe(18) ≈ 144비트.
_TEMP_PASSWORD_BYTES: Final = 18


@dataclass(frozen=True, slots=True)
class BootstrapOutcome:
    """부트스트랩 결과.

    ``console_notice`` 는 **생성된 경우에만** 채워지며, 호출자가 콘솔에
    출력한 뒤 폐기합니다. 저장되는 것은 적응형 해시뿐입니다.
    """

    created: bool
    username: str | None = None
    console_notice: SecretStr | None = None


class AdminBootstrapper:
    def __init__(
        self,
        *,
        accounts: AccountRepositoryPort,
        hasher: PasswordHasherPort,
        audit: AuditTrailPort,
        clock: ClockPort,
    ) -> None:
        self._accounts = accounts
        self._hasher = hasher
        self._audit = audit
        self._clock = clock

    def bootstrap(self) -> BootstrapOutcome:
        """활성 관리자가 없을 때만 생성하거나 복구한다. 멱등."""
        if self._accounts.count_active_admins() >= 1:
            # ⭐ 아무것도 변경하지 않습니다 — 속성 1 의 핵심.
            return BootstrapOutcome(created=False)

        now = self._clock.now()
        temp_password = SecretStr(secrets.token_urlsafe(_TEMP_PASSWORD_BYTES))
        username = Username.parse(BOOTSTRAP_USERNAME)

        # ⭐ 기존 admin 계정이 비활성 상태로 남아 있으면 **재활성화**합니다.
        #
        #    사용자명은 전역 유일하므로(INV-AC-02), 비활성 admin 이 남아 있는
        #    상태에서 새 admin 을 만들면 유일 제약에 걸려 복구가 불가능해집니다.
        #    런북 R2(관리자 잠김 복구)가 이 경로에 의존합니다.
        #
        #    이 상태에 도달하려면 DB 를 직접 수정해야 합니다 — BR-AD-03 이
        #    정상 경로에서 관리자 0명을 막기 때문입니다. 즉 이미 파일 접근
        #    권한이 있는 사람만 쓸 수 있는 복구 수단입니다.
        existing = self._accounts.find_by_username(username)

        if existing is not None:
            account = (
                existing.with_password(self._hasher.hash(temp_password), now=now, must_change=True)
                .with_role(Role.ADMIN, now=now)
                .with_active(True, now=now)
            )
        else:
            account = Account(
                id=UserId.generate(),
                username=username,
                display_name=BOOTSTRAP_USERNAME,
                password_hash=self._hasher.hash(temp_password),
                role=Role.ADMIN,
                is_active=True,
                must_change_password=True,  # AC-18 — 최초 로그인 시 변경 강제
                created_at=now,
                updated_at=now,
            )

        try:
            self._accounts.save(account)
        except ConflictError:
            # 동시 기동 경쟁 (BR-BS-08). 다른 프로세스가 먼저 만들었으므로
            # 우리는 아무것도 하지 않은 것으로 처리합니다.
            return BootstrapOutcome(created=False)

        self._audit.append(
            AuditEntry(
                event_type=AuditEventType.ADMIN_BOOTSTRAPPED,
                outcome=AuditOutcome.SUCCEEDED,
                occurred_at=now,
                actor_user_id=account.id,
                actor_role=Role.ADMIN,
                target_ref=f"account:{account.id}",
                # ⚠ 임시 비밀번호를 담지 않습니다. 담으려 해도 detail 이
                #   Redactable 타입이라 SecretStr 이 들어갈 수 없습니다.
                detail={"username": BOOTSTRAP_USERNAME},
            )
        )

        return BootstrapOutcome(
            created=True,
            username=BOOTSTRAP_USERNAME,
            console_notice=temp_password,
        )
