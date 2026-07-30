# Personal Health Coach

개인 맞춤 건강관리 추천 시스템 — 로컬 실행 데스크톱 앱 + 브라우저 UI.

> ⚠ **이 도구는 웰니스 · 정보 제공 목적입니다.**
> 진단 · 치료 · 처방을 수행하지 않으며 의료기기가 아닙니다. 건강 관련 결정은 전문가와 상의하십시오.

---

## 현재 상태

**Unit 1A (기반·인증·운영) 구현 중** — `v0.1.0`

| 유닛 | 내용 | 상태 |
|---|---|---|
| **1A** | 기반 · 인증 · 운영 | 🔨 진행 중 |
| 1B | 데이터 · 지식 | 예정 |
| 1C | 안전 · 추천 | 예정 |
| 1D | 대화 · 피드백 · 대시보드 | 예정 (MVP 완성) |

---

## 설치와 실행

> 상세 절차는 Unit 1A 완료 시(S40) 채워집니다.

```powershell
# 1. 의존성 설치
uv sync --locked --all-extras

# 2. 설정 파일 준비
#    .env.example 을 %LOCALAPPDATA%\PersonalHealthCoach\config\.env 로 복사

# 3. 실행
uv run phc
```

**최초 기동 시**: 관리자 계정이 자동 생성되고 **임시 비밀번호가 콘솔에 1회만 출력**됩니다.
이 값은 로그·파일 어디에도 저장되지 않으므로 반드시 기록해 두십시오. 최초 로그인 시 비밀번호 변경이 강제됩니다.

---

## 프로젝트 구조

```
src/phc/
├── shared/       공유 커널 — 타입 · 오류 · 시각 · 암호화 포트
├── operations/   작업 큐 · 백업 · 관측성 · 감사
├── identity/     계정 · 세션 · 인가          <- 경계 B
├── knowledge/    참조 지식베이스              (1B)
├── safety/       안전 규칙 판정               (1C) <- 경계 A 주체
├── generation/   LLM 생성 (가드 적용)         (1C) <- 경계 A 대상
├── healthdata/   프로필 · 측정 · 취입         (1B) <- 경계 B
├── advisory/     추천 · 대화 · 피드백         (1C/1D)
└── web/          표현 계층

tests/
├── unit/         예시 기반 테스트
├── property/     Hypothesis 속성 테스트
└── integration/  통합 · 경계 린트 검증
```

**데이터는 저장소 밖에 있습니다** — `%LOCALAPPDATA%\PersonalHealthCoach\`.
코드와 데이터를 분리하여 건강 데이터가 Git 에 커밋되는 사고를 구조적으로 막습니다.

---

## 두 개의 경계

이 프로젝트에는 코드로 강제되는 두 경계가 있습니다. 둘 다 `.importlinter` 계약이 CI 에서 검사합니다.

### 경계 A — 규칙 계층 ↔ LLM 계층 (Unit 1C)

`GuardedGenerationPort` 가 도메인에 노출되는 **유일한 생성 통로**입니다.
`RawLlmAdapter` 와 `LlmPort` 는 `generation` 모듈 밖으로 나가지 않으므로,
안전 검증을 건너뛰고 LLM 을 호출하는 코드는 **작성할 방법이 없습니다**.

### 경계 B — 계정 도메인 ↔ 건강 데이터 도메인 (Unit 1A)

`identity` 는 `healthdata` · `advisory` 를 참조하지 않습니다.
건강 데이터 접근은 `OwnerScope` 를 필수로 요구하고, `OwnerScope` 는 인증된 주체로부터만 생성됩니다.
소유권 판정은 **역할을 보지 않습니다** — 관리자에게도 예외가 없습니다.

> ⚠ **이 보장의 범위**: 경계 B 는 **애플리케이션을 통한 접근**에 적용됩니다.
> 모든 사용자의 데이터가 하나의 DB 파일에 있으므로, 그 파일에 OS 수준으로 접근할 수 있는 사람은
> 타인의 데이터를 열람할 수 있습니다. 같은 Windows 계정을 공유하는 환경에서는 이 점을 고려하십시오.

---

## 개발

```powershell
uv run ruff check .              # 린트
uv run mypy                      # 타입 검사
uv run lint-imports              # 모듈 경계 (경계 A·B)
uv run pytest tests/unit         # 단위 테스트
uv run pytest tests/property     # 속성 테스트 (Hypothesis)
```

CI 는 이 9개 게이트를 `windows-latest` 에서 실행합니다.
DPAPI 어댑터가 Windows 전용이라, Linux 러너에서는 "테스트는 통과하는데 실제로는 안 되는" 상태가 만들어지기 때문입니다.

---

## 설계 문서

`../aidlc-docs/` — 요구사항 · 사용자 스토리 · 애플리케이션 설계 · 유닛별 상세 설계
