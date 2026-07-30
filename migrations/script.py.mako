"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

⚠ 리비전 식별자는 BackupArtifact.schema_version 이 됩니다 (BR-BK-07).
   4자리 순번(0002, 0003 ...)으로 지정하십시오 — 해시를 쓰면 백업 메타데이터만
   보고 전후 관계를 판정할 수 없습니다.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | None = ${repr(branch_labels)}
depends_on: str | None = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
