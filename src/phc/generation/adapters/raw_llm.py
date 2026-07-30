"""원시 LLM 어댑터 — ⚠ generation 모듈 **내부 전용**.

경계 A (FR-12 / FR-14 / FR-28, RSK-02 / RSK-03 / RSK-09):
    이 어댑터는 DI 컨테이너에서 ``generation`` 모듈 밖으로 바인딩되지 않습니다.
    다른 컴포넌트가 안전 검증을 건너뛰고 LLM 을 호출하는 코드는
    **애초에 작성할 수 없어야** 합니다.

    이 규칙은 ``.importlinter`` 계약 C3 가 기계적으로 강제합니다.

소유 유닛:
    **Unit 1C (안전·추천)**. 이 파일은 Unit 1A 에서 **자리만** 만들어 둔 것입니다.
    자세한 근거는 ``phc.generation.ports.llm`` 의 설명을 참조하십시오.
"""

from __future__ import annotations

__all__: list[str] = []

# Unit 1C 에서 RawLlmAdapter(LlmPort 구현)를 정의합니다.
# 명시적 타임아웃 필수 (NFR-15, RESILIENCY-10).
# 지금은 의도적으로 비어 있습니다.
