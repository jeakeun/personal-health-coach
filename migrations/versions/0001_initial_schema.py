"""초기 스키마 — Unit 1A (계정·운영 테이블 11종)

Revision ID: 0001
Revises:
Create Date: 2026-07-28

⭐ **이 리비전 번호가 곧 ``BackupArtifact.schema_version`` 입니다** (BR-BK-07).
   1A 에서 만든 백업은 ``schema_version="0001"`` 로 기록되고, 1B 에서 건강 데이터
   테이블이 추가되면 ``"0002"`` 가 됩니다. 복원 시 백업 버전이 앱 버전보다 뒤이면
   거부합니다 — 앱이 모르는 스키마를 되돌리는 셈이기 때문입니다.

⚠ **이 파일은 ``schema.py`` 의 사본이 아니라 두 번째 진술입니다.**
   둘이 어긋나면 "테스트는 통과하는데 실제 DB 는 다른" 상태가 됩니다.
   ``tests/integration/test_migrations.py`` 가 마이그레이션으로 만든 DB 와
   ``METADATA.create_all()`` 로 만든 DB 를 실제로 대조하여 이를 막습니다.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None

#: 생성 순서. 되돌릴 때는 역순입니다.
_TABLES = (
    "accounts",
    "sessions",
    "login_attempts",
    "throttle_states",
    "mfa_enrollments",
    "mfa_recovery_codes",
    "audit_entries",
    "audit_archives",
    "jobs",
    "backup_artifacts",
    "alerts",
)


def upgrade() -> None:
    # -----------------------------------------------------------------------
    # 계정 도메인
    # -----------------------------------------------------------------------
    op.create_table(
        "accounts",
        sa.Column("id", sa.String(length=64), nullable=False),
        # 정규화된 사용자명. 유일 제약이 INV-AC-02 의 최종 방어입니다 —
        # 사전 조회만으로는 동시 가입 경쟁을 막을 수 없습니다.
        sa.Column("username", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=64), nullable=False),
        # ⚠ 평문 비밀번호 컬럼이 존재하지 않습니다 (INV-AC-01, 🔬 속성 2).
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        # ⚠ 이메일 컬럼이 존재하지 않습니다 (INV-AC-04, F1=A, NFR-34).
        sa.PrimaryKeyConstraint("id", name="pk_accounts"),
        sa.UniqueConstraint("username", name="uq_accounts_username"),
    )
    op.create_index("ix_accounts_role_active", "accounts", ["role", "is_active"])

    op.create_table(
        "sessions",
        # ⚠ 토큰 원문이 아니라 해시입니다 (INV-SE-03).
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("token_hash", name="pk_sessions"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_absolute_expires_at", "sessions", ["absolute_expires_at"])

    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        # ⚠ 계정 외래키가 없습니다. 존재하지 않는 사용자명의 시도도 기록해야
        #    응답 시간으로 계정 존재가 드러나지 않습니다 (BR-TH-11).
        sa.Column("username_normalized", sa.String(length=32), nullable=False),
        sa.Column("client_key", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_login_attempts"),
    )
    op.create_index(
        "ix_login_attempts_username_occurred",
        "login_attempts",
        ["username_normalized", "occurred_at"],
    )
    op.create_index("ix_login_attempts_occurred_at", "login_attempts", ["occurred_at"])

    op.create_table(
        "throttle_states",
        sa.Column("username_normalized", sa.String(length=32), nullable=False),
        sa.Column("client_key", sa.String(length=64), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("first_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        # ⭐ 잠금 상태를 DB 에 둡니다 (ND6=A). 인메모리로 두면 앱을 재시작시킬 수
        #    있는 공격자에게 잠금이 무의미해집니다.
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("username_normalized", "client_key", name="pk_throttle_states"),
    )

    op.create_table(
        "mfa_enrollments",
        sa.Column("user_id", sa.String(length=64), nullable=False),
        # ⚠ 암호문입니다. 평문 비밀키 컬럼이 존재하지 않습니다 (INV-MF-01).
        sa.Column("secret_cipher", sa.LargeBinary(), nullable=False),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        # NULL 이면 MFA 미활성 — 확인 전 상태 (INV-MF-02).
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("user_id", name="pk_mfa_enrollments"),
    )

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        # ⚠ 적응형 해시입니다. 평문 복구 코드는 저장하지 않습니다 (INV-RC-01).
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_recovery_codes"),
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])

    # -----------------------------------------------------------------------
    # 운영 도메인
    # -----------------------------------------------------------------------
    op.create_table(
        "audit_entries",
        # 단조 증가. 결번은 변조 신호입니다 (INV-AU-03).
        sa.Column("seq", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("actor_user_id", sa.String(length=64), nullable=True),
        sa.Column("actor_role", sa.String(length=16), nullable=True),
        sa.Column("target_ref", sa.String(length=128), nullable=True),
        sa.Column("correlation_id", sa.String(length=32), nullable=True),
        # ⚠ Redactable 만 담깁니다 (INV-AU-02).
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("seq", name="pk_audit_entries"),
    )
    op.create_index("ix_audit_entries_occurred_at", "audit_entries", ["occurred_at"])
    op.create_index(
        "ix_audit_entries_event_type_occurred",
        "audit_entries",
        ["event_type", "occurred_at"],
    )

    op.create_table(
        "audit_archives",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("covers_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("covers_to", sa.DateTime(timezone=True), nullable=False),
        # 결번 검증용 구간 (BR-AU-05).
        sa.Column("seq_from", sa.Integer(), nullable=False),
        sa.Column("seq_to", sa.Integer(), nullable=False),
        sa.Column("artifact_ref", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_archives"),
    )

    op.create_table(
        "jobs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        # ⭐ 워커가 이 값으로 OwnerScope 를 재구성합니다 (BR-JQ-07, 경계 B).
        sa.Column("owner_id", sa.String(length=64), nullable=False),
        # ⚠ 참조만 담습니다. 민감값을 직접 담지 않습니다 (BR-JQ-09).
        sa.Column("payload_ref", sa.Text(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.String(length=64), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("result_ref", sa.Text(), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_jobs"),
    )
    # ⭐ claim 쿼리의 근거 인덱스 (NFR-1A-04, 50ms 예산).
    op.create_index("ix_jobs_state_next_attempt", "jobs", ["state", "next_attempt_at"])
    # 회수 스캔 (BR-JQ-04).
    op.create_index("ix_jobs_state_heartbeat", "jobs", ["state", "heartbeat_at"])

    op.create_table(
        "backup_artifacts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("artifact_ref", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        # ⚠ 키 자체가 아니라 SecretStorePort 의 **키 이름**입니다.
        sa.Column("cipher_key_ref", sa.String(length=64), nullable=False),
        # ⭐ 이 컬럼에 들어가는 값이 위 revision 문자열입니다 (BR-BK-07).
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_backup_artifacts"),
    )
    op.create_index("ix_backup_artifacts_created_at", "backup_artifacts", ["created_at"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("raised_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("context", sa.JSON(), nullable=False),
        # NULL 이면 미확인 — 확인 표시 전까지 대시보드에 남습니다 (ND2=A).
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_alerts"),
    )
    op.create_index("ix_alerts_kind_raised", "alerts", ["kind", "raised_at"])
    op.create_index("ix_alerts_acknowledged_at", "alerts", ["acknowledged_at"])


def downgrade() -> None:
    """⚠ 전체 삭제입니다 — 데이터가 사라집니다.

    롤백 절차는 "이전 아티팩트 재배포 + 백업 복원"(R5=A)이며, 이 함수를 운영
    DB 에 실행하는 것이 아닙니다. 여기 있는 이유는 마이그레이션이 실제로
    되돌릴 수 있는지 테스트가 확인하기 위해서입니다.
    """
    for table in reversed(_TABLES):
        op.drop_table(table)
