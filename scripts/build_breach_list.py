"""유출 비밀번호 목록 번들 생성 (S19, NFR-41 · NFR-1A-20).

입력으로 받은 평문 비밀번호 목록을 **SHA-1 대문자 16진 해시**로 변환해
``FileBreachedPasswordList`` 가 읽을 수 있는 번들을 만듭니다.

왜 이 스크립트가 따로 있는가:

1. **평문 목록을 저장소에 두지 않기 위해** — 커밋되는 것은 해시뿐입니다.
2. **원본은 대용량이라 커밋하지 않기 위해** — 원본은 ``scripts/_downloads/``
   에 두고 ``.gitignore`` 로 제외합니다.
3. 오프라인 동작을 지키기 위해 (CON-02). 외부 API 조회를 쓰지 않으므로
   목록을 미리 준비해 두어야 합니다.

**범위 한계 (정직하게)**: 상위 N건만 담으므로 최신 유출 전량을 막지
못합니다. 오프라인 동작을 지키기 위한 의도적 절충입니다 (BR-PW-02).

사용:
    # 1) 공개된 유출 비밀번호 목록(평문, 한 줄에 하나)을 내려받아 둡니다.
    #    예: SecLists 의 상위 비밀번호 목록
    # 2) 해시 번들로 변환합니다.
    python scripts/build_breach_list.py \
        --input scripts/_downloads/top-passwords.txt \
        --output src/phc/identity/data/breached-sha1.txt \
        --limit 100000
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

#: NFR-1A-20 — 이 미만이면 경고합니다.
MIN_RECOMMENDED_ENTRIES = 100_000


def build(source: Path, target: Path, limit: int | None) -> int:
    """평문 목록을 해시 번들로 변환하고 항목 수를 반환한다."""
    digests: set[str] = set()

    with source.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            password = line.rstrip("\r\n")
            if not password:
                continue
            digests.add(
                hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
            )
            if limit is not None and len(digests) >= limit:
                break

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(sorted(digests)), encoding="utf-8")
    return len(digests)


def main() -> int:
    parser = argparse.ArgumentParser(description="유출 비밀번호 해시 번들 생성")
    parser.add_argument("--input", required=True, type=Path, help="평문 목록 (한 줄에 하나)")
    parser.add_argument("--output", required=True, type=Path, help="해시 번들 출력 경로")
    parser.add_argument("--limit", type=int, default=MIN_RECOMMENDED_ENTRIES)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"[실패] 입력 파일이 없습니다: {args.input}", file=sys.stderr)
        print(
            "       공개 유출 비밀번호 목록을 내려받아 scripts/_downloads/ 에 두십시오.\n"
            "       (해당 디렉터리는 .gitignore 로 제외되어 있습니다.)",
            file=sys.stderr,
        )
        return 2

    count = build(args.input, args.output, args.limit)
    print(f"[완료] {count:,}건을 {args.output} 에 기록했습니다.")

    if count < MIN_RECOMMENDED_ENTRIES:
        # ⚠ 실패시키지는 않습니다 — 개발 환경에서 작은 목록으로 돌릴 수 있어야
        #    하기 때문입니다. 다만 운영 기준 미달임을 분명히 알립니다.
        print(
            f"[경고] 권장 최소 항목 수({MIN_RECOMMENDED_ENTRIES:,})에 미달합니다. "
            f"운영 배포 전에 목록을 보강하십시오 (NFR-1A-20).",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
