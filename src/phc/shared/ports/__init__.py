"""공유 커널 — 포트 (인터페이스).

어댑터 구현은 ``phc.infrastructure`` 에 있습니다. 도메인은 포트만 알고
구현을 모릅니다 (D1=B 헥사고날, 계약 C4).
"""

from __future__ import annotations

from phc.shared.ports.cipher import CipherPort, CipherPurpose
from phc.shared.ports.clock import ClockPort
from phc.shared.ports.secret_store import SecretStorePort

__all__ = ["CipherPort", "CipherPurpose", "ClockPort", "SecretStorePort"]
