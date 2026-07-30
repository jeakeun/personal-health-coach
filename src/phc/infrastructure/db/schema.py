"""SQLAlchemy **Core** 스키마 정의 (S27, D-04).

⚠ ORM 을 쓰지 않습니다. 도메인 모델이 SQLAlchemy 클래스에 종속되면
   인메모리 리포지토리로 대체 테스트할 수 없게 되고, 그것이 곧 NFR-1A-38
   판정 실패입니다. 여기 있는 것은 **테이블 메타데이터뿐**이며 도메인 객체와
   매핑은 어댑터가 손으로 합니다.

⚠ 이 모듈은 ``phc.*.domain`` 에서 import 되지 않습니다 (계약 C4).
   의존 방향은 어댑터 -> 스키마 한 방향입니다.

인덱스 전략 (nfr-design-patterns.md §3.1):
    accounts.username         유일 — 로그인 조회 + 중복 방지 이중 목적
    sessions.token_hash       유일 — 매 요청 조회 (NFR-1A-08, 10ms 예산)
    sessions.user_id          전량 무효화
    sessions.absolute_expires_at  만료 정리 스캔
    throttle_states.key       유일 — 로그인마다 조회
    audit_entries.seq         기본키(단조 증가) — 결번 검증
    audit_entries.occurred_at 기간 조회·아카이브 이관
    jobs(state, next_attempt_at)  복합 — claim 쿼리 (NFR-1A-04, 50ms 예산)
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
)

__all__ = [
    "METADATA",
    "accounts",
    "alerts",
    "audit_archives",
    "audit_entries",
    "backup_artifacts",
    "jobs",
    "login_attempts",
    "mfa_enrollments",
    "mfa_recovery_codes",
    "sessions",
    "throttle_states",
]

#: 제약 이름을 규칙으로 고정합니다. 이름이 자동 생성되면 Alembic 이
#: 마이그레이션에서 제약을 찾지 못해 이후 변경이 어려워집니다.
_NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

METADATA = MetaData(naming_convention=_NAMING)


# ---------------------------------------------------------------------------
# 계정 도메인
#
# ⚠ 이 테이블들은 OwnerScope 로 접근하지 않습니다. 관리자 기능이 성립해야
#    하기 때문입니다. 건강 데이터 테이블(1B 이후)은 반대로 OwnerScope 를
#    필수로 요구합니다 — 그 비대칭이 경계 B 의 형태입니다.
# ---------------------------------------------------------------------------
accounts = Table(
    "accounts",
    METADATA,
    Column("id", String(64), primary_key=True),
    # 정규화된 사용자명. 유일 제약이 INV-AC-02 의 최종 방어입니다 —
    # 사전 조회만으로는 동시 가입 경쟁을 막을 수 없습니다.
    Column("username", String(32), nullable=False, unique=True),
    Column("display_name", String(64), nullable=False),
    # ⚠ 평문 비밀번호 컬럼이 존재하지 않습니다 (INV-AC-01, 🔬 속성 2).
    Column("password_hash", Text, nullable=False),
    Column("role", String(16), nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("must_change_password", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("last_login_at", DateTime(timezone=True), nullable=True),
    # ⚠ 이메일 컬럼이 존재하지 않습니다 (INV-AC-04, F1=A, NFR-34).
    Index("ix_accounts_role_active", "role", "is_active"),
)

sessions = Table(
    "sessions",
    METADATA,
    # ⚠ 토큰 원문이 아니라 해시입니다 (INV-SE-03).
    Column("token_hash", String(64), primary_key=True),
    Column("user_id", String(64), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("idle_expires_at", DateTime(timezone=True), nullable=False),
    Column("absolute_expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
    Index("ix_sessions_user_id", "user_id"),
    Index("ix_sessions_absolute_expires_at", "absolute_expires_at"),
)

login_attempts = Table(
    "login_attempts",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    # ⚠ 계정 외래키가 없습니다. 존재하지 않는 사용자명의 시도도 기록해야
    #    응답 시간으로 계정 존재가 드러나지 않습니다 (BR-TH-11).
    Column("username_normalized", String(32), nullable=False),
    Column("client_key", String(64), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("outcome", String(24), nullable=False),
    Index("ix_login_attempts_username_occurred", "username_normalized", "occurred_at"),
    Index("ix_login_attempts_occurred_at", "occurred_at"),
)

throttle_states = Table(
    "throttle_states",
    METADATA,
    Column("username_normalized", String(32), primary_key=True),
    Column("client_key", String(64), primary_key=True),
    Column("consecutive_failures", Integer, nullable=False, default=0),
    Column("first_failure_at", DateTime(timezone=True), nullable=True),
    Column("last_failure_at", DateTime(timezone=True), nullable=True),
    # ⭐ 잠금 상태를 DB 에 둡니다 (ND6=A). 인메모리로 두면 앱을 재시작시킬 수
    #    있는 공격자에게 잠금이 무의미해집니다.
    Column("locked_until", DateTime(timezone=True), nullable=True),
)

mfa_enrollments = Table(
    "mfa_enrollments",
    METADATA,
    Column("user_id", String(64), primary_key=True),
    # ⚠ 암호문입니다. 평문 비밀키 컬럼이 존재하지 않습니다 (INV-MF-01).
    Column("secret_cipher", LargeBinary, nullable=False),
    Column("enrolled_at", DateTime(timezone=True), nullable=False),
    # NULL 이면 MFA 미활성 — 확인 전 상태 (INV-MF-02).
    Column("confirmed_at", DateTime(timezone=True), nullable=True),
)

mfa_recovery_codes = Table(
    "mfa_recovery_codes",
    METADATA,
    Column("id", String(64), primary_key=True),
    Column("user_id", String(64), nullable=False),
    # ⚠ 적응형 해시입니다. 평문 복구 코드는 저장하지 않습니다 (INV-RC-01).
    Column("code_hash", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True), nullable=True),
    Index("ix_mfa_recovery_codes_user_id", "user_id"),
)


# ---------------------------------------------------------------------------
# 운영 도메인
# ---------------------------------------------------------------------------
audit_entries = Table(
    "audit_entries",
    METADATA,
    # 단조 증가. 결번은 변조 신호입니다 (INV-AU-03).
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("event_type", String(48), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("actor_user_id", String(64), nullable=True),
    Column("actor_role", String(16), nullable=True),
    Column("target_ref", String(128), nullable=True),
    Column("correlation_id", String(32), nullable=True),
    # ⚠ Redactable 만 담깁니다 (INV-AU-02). 민감 타입은 애플리케이션 계층에서
    #    타입 검사로 차단되므로 여기 도달하지 않습니다.
    Column("detail", JSON, nullable=False, default=dict),
    Index("ix_audit_entries_occurred_at", "occurred_at"),
    Index("ix_audit_entries_event_type_occurred", "event_type", "occurred_at"),
)

audit_archives = Table(
    "audit_archives",
    METADATA,
    Column("id", String(64), primary_key=True),
    Column("covers_from", DateTime(timezone=True), nullable=False),
    Column("covers_to", DateTime(timezone=True), nullable=False),
    # 결번 검증용 구간 (BR-AU-05).
    Column("seq_from", Integer, nullable=False),
    Column("seq_to", Integer, nullable=False),
    Column("artifact_ref", Text, nullable=False),
    Column("checksum", String(64), nullable=False),
    Column("archived_at", DateTime(timezone=True), nullable=False),
)

jobs = Table(
    "jobs",
    METADATA,
    Column("id", String(64), primary_key=True),
    Column("kind", String(32), nullable=False),
    # ⭐ 워커가 이 값으로 OwnerScope 를 재구성합니다 (BR-JQ-07, 경계 B).
    Column("owner_id", String(64), nullable=False),
    # ⚠ 참조만 담습니다. 민감값을 직접 담지 않습니다 (BR-JQ-09).
    Column("payload_ref", Text, nullable=False, default=""),
    Column("state", String(16), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("max_attempts", Integer, nullable=False, default=3),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("next_attempt_at", DateTime(timezone=True), nullable=True),
    Column("claimed_by", String(64), nullable=True),
    Column("heartbeat_at", DateTime(timezone=True), nullable=True),
    Column("progress_percent", Integer, nullable=False, default=0),
    Column("result_ref", Text, nullable=True),
    Column("error_summary", Text, nullable=True),
    # ⭐ claim 쿼리의 근거 인덱스 (NFR-1A-04, 50ms 예산).
    Index("ix_jobs_state_next_attempt", "state", "next_attempt_at"),
    # 회수 스캔 (BR-JQ-04).
    Index("ix_jobs_state_heartbeat", "state", "heartbeat_at"),
)

backup_artifacts = Table(
    "backup_artifacts",
    METADATA,
    Column("id", String(64), primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("artifact_ref", Text, nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("checksum", String(64), nullable=False),
    # ⚠ 키 자체가 아니라 SecretStorePort 의 **키 이름**입니다.
    Column("cipher_key_ref", String(64), nullable=False),
    # ⭐ 유닛마다 스키마가 확장되므로 필수 (BR-BK-07).
    Column("schema_version", String(32), nullable=False),
    Column("verified_at", DateTime(timezone=True), nullable=True),
    Index("ix_backup_artifacts_created_at", "created_at"),
)

alerts = Table(
    "alerts",
    METADATA,
    Column("id", String(64), primary_key=True),
    Column("kind", String(48), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("raised_at", DateTime(timezone=True), nullable=False),
    Column("summary", Text, nullable=False),
    Column("context", JSON, nullable=False, default=dict),
    # NULL 이면 미확인 — 확인 표시 전까지 대시보드에 남습니다 (ND2=A).
    Column("acknowledged_at", DateTime(timezone=True), nullable=True),
    Index("ix_alerts_kind_raised", "kind", "raised_at"),
    Index("ix_alerts_acknowledged_at", "acknowledged_at"),
)
