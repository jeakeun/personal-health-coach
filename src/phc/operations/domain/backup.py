"""백업 도메인.

``schema_version`` 이 여기 있는 이유:
    US-37/38(백업·복구)이 Unit 1A 에 있어 백업은 계정 테이블만 존재하는
    상태에서 처음 만들어집니다. 이후 1B 에서 건강 데이터, 1C 에서 추천,
    1D 에서 대화 이력 테이블이 추가됩니다.

    버전 없이 복원하면 **구버전 백업이 신버전 앱에 조용히 잘못 적재**됩니다.
    그래서 복원 전에 버전을 비교하고, 앱보다 높은 버전은 거부합니다 (BR-BK-07).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

__all__ = ["BackupArtifact", "BackupId", "RetentionPolicy"]


@dataclass(frozen=True, slots=True, order=True)
class BackupId:
    value: str

    @classmethod
    def generate(cls) -> BackupId:
        return cls(uuid.uuid4().hex)

    def __str__(self) -> str:
        return self.value

    def __redacted_repr__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class BackupArtifact:
    """백업 산출물 메타데이터.

    ⚠ 파일명·메타데이터에 사용자명·건강 데이터가 드러나지 않습니다 (BR-BK-09).
    본문은 항상 암호화되어 보관됩니다 (INV-BK-01).
    """

    id: BackupId
    created_at: datetime
    artifact_ref: str
    size_bytes: int
    checksum: str
    #: 암호화 키 자체가 아니라 SecretStorePort 의 **키 이름**입니다.
    cipher_key_ref: str
    #: Alembic 리비전과 연동됩니다.
    schema_version: str
    #: 테스트 복원으로 검증한 시각. 리허설 경과 추적에 사용됩니다.
    verified_at: datetime | None = None

    def is_restorable_onto(self, app_schema_version: str, known_order: list[str]) -> bool:
        """이 백업을 현재 앱에 복원해도 되는가 (BR-BK-07).

        백업 버전이 앱 버전보다 **뒤**이면 거부합니다. 앱이 모르는 스키마를
        되돌리는 셈이라 무엇이 깨질지 알 수 없습니다.
        """
        if self.schema_version not in known_order or app_schema_version not in known_order:
            return False
        return known_order.index(self.schema_version) <= known_order.index(app_schema_version)

    def needs_reverification(self, now: datetime, max_age: timedelta) -> bool:
        """복원 리허설이 오래되었는가.

        "리허설을 하기로 한 것" 과 "실제로 하는 것" 은 다릅니다.
        시스템이 상기시키게 합니다 (Infrastructure Design §9).
        """
        if self.verified_at is None:
            return True
        return now - self.verified_at > max_age

    def __redacted_repr__(self) -> str:
        return f"BackupArtifact(id={self.id}, schema={self.schema_version})"


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """세대 보관 정책 (I3=A). 일 7 + 주 4 + 월 3 = 최대 14개."""

    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 3

    def select_expired(self, artifacts: list[BackupArtifact]) -> list[BackupArtifact]:
        """정리 대상을 고른다. 최신순으로 일·주·월 슬롯을 채우고 나머지를 반환."""
        ordered = sorted(artifacts, key=lambda a: a.created_at, reverse=True)
        keep: set[BackupId] = set()

        for artifact in ordered[: self.keep_daily]:
            keep.add(artifact.id)

        seen_weeks: set[tuple[int, int]] = set()
        for artifact in ordered:
            if len(seen_weeks) >= self.keep_weekly:
                break
            iso = artifact.created_at.isocalendar()
            key = (iso.year, iso.week)
            if key not in seen_weeks:
                seen_weeks.add(key)
                keep.add(artifact.id)

        seen_months: set[tuple[int, int]] = set()
        for artifact in ordered:
            if len(seen_months) >= self.keep_monthly:
                break
            key = (artifact.created_at.year, artifact.created_at.month)
            if key not in seen_months:
                seen_months.add(key)
                keep.add(artifact.id)

        return [a for a in ordered if a.id not in keep]
