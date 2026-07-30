"""계정 · 세션 · 인가 — ⭐ 경계 B 를 소유하는 모듈.

이 모듈은 ``healthdata`` · ``advisory`` 를 **import 할 수 없습니다**
(계약 C2). 관리자 권한이 건강 데이터에 닿는 코드 경로가 애초에 만들어질 수
없다는 뜻입니다 (FR-39, US-48, RSK-10).

경계 B 의 세 겹:

    1. 의존 방향 차단      계약 C2 (pyproject.toml)
    2. API 표면 우회 부재  phc.shared.scope.OwnerScope — 인증 주체로만 생성
    3. 역할 무관 불변식    OwnershipAuthorizer.require_owner — ctx.role 미참조

⚠ 이 보장의 범위는 **애플리케이션 경로**입니다. 모든 사용자의 데이터가 하나의
   DB 파일에 있으므로, 그 파일에 OS 수준으로 접근할 수 있는 사람은 타인의
   데이터를 열람할 수 있습니다 (Infrastructure Design §7).
"""

from __future__ import annotations

__all__: list[str] = []
