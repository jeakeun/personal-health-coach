"""LLM 프로바이더 포트 — ⚠ generation 모듈 **내부 전용**.

경계 A (FR-12 / FR-14 / FR-28):
    이 모듈은 ``generation`` 밖으로 import 되어서는 안 됩니다.
    도메인 서비스에 노출되는 유일한 생성 통로는 ``GuardedGenerationPort`` 이며,
    ``GuardedGenerator`` 가 호출 전후로 ``SafetyRuleEngine`` 을 반드시 통과시킵니다.

    이 규칙은 ``.importlinter`` 계약 C3 가 기계적으로 강제합니다.

소유 유닛:
    **Unit 1C (안전·추천)**. 이 파일은 Unit 1A 에서 **자리만** 만들어 둔 것입니다.
    계약 C3 가 대상 모듈을 필요로 하기 때문이며, 구현은 1C 에서 채웁니다.
    모듈이 만들어지는 시점에 규칙이 이미 존재해야 위반 코드가 커밋되지 않습니다.
"""

from __future__ import annotations

__all__: list[str] = []

# Unit 1C 에서 LlmPort 프로토콜(complete / stream / is_available)을 정의합니다.
# 지금은 의도적으로 비어 있습니다.
