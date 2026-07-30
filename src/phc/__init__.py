"""Personal Health Coach — 개인 맞춤 건강관리 추천 시스템.

⚠ 이 시스템은 **웰니스 · 정보 제공 도구**입니다.
   진단 · 치료 · 처방을 수행하지 않으며 의료기기가 아닙니다 (NFR-32).

모듈 구성 (도메인 바운디드 컨텍스트):

    shared        공유 커널 — 타입 · 오류 · 시각 · 암호화 포트
    operations    작업 큐 · 백업 · 관측성 · 감사
    identity      계정 · 세션 · 인가                    <- 경계 B 의 한쪽
    knowledge     참조 지식베이스                        (Unit 1B)
    safety        안전 규칙 판정                         (Unit 1C) <- 경계 A 의 주체
    generation    LLM 생성 (가드 적용)                   (Unit 1C) <- 경계 A 의 대상
    healthdata    프로필 · 측정 지표 · 취입              (Unit 1B) <- 경계 B 의 다른 쪽
    advisory      추천 · 대화 · 피드백                   (Unit 1C/1D)
    web           표현 계층

의존 위계 (거슬러 올라가지 않음):

    shared <- operations <- knowledge
                         <- identity <- healthdata
                         <- safety <- generation <- advisory <- web

두 경계는 ``.importlinter`` 계약 C2 · C3 가 기계적으로 강제합니다.
"""

from __future__ import annotations

__version__ = "0.1.0"
