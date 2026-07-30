"""모듈 단위 커버리지 임계값 검사 (NFR-1A-34).

전체 커버리지 80% 는 ``pyproject.toml`` 의 ``fail_under`` 가 담당합니다.
이 스크립트는 그것만으로는 잡히지 않는 것을 검사합니다 — 특정 모듈이
전체 평균 뒤에 숨는 상황입니다.

``identity`` 는 경계 B 를 소유하는 모듈이라 90% 를 요구합니다. 전체가 85% 여도
``identity`` 가 70% 라면 그 사실이 드러나야 합니다.

사용:
    python scripts/check_module_coverage.py --module phc.identity --min 90
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# 린트 예외 사유 (S314, 아래 measure() 안):
#   여기서 파싱하는 coverage.xml 은 바로 앞 CI 단계에서 우리 도구가 생성한
#   산출물입니다. 신뢰할 수 없는 입력이 아니므로 defusedxml 의존성을 추가하지
#   않습니다. 외부 입력을 파싱하게 되는 날에는 이 판단을 다시 해야 합니다.


def module_to_path_prefix(module: str) -> str:
    """``phc.identity`` -> ``phc/identity``."""
    return module.replace(".", "/")


def measure(coverage_xml: Path, prefix: str) -> tuple[int, int]:
    """해당 접두사에 속한 파일들의 (커버된 줄, 전체 줄)을 합산한다.

    ⚠ coverage.xml 의 ``filename`` 은 ``<source>`` 기준 **상대 경로**입니다.
    예: source=``.../src/phc`` 이면 filename 은 ``identity/domain/account.py``.
    따라서 ``phc.identity`` 같은 모듈 경로로 바로 대조하면 하나도 맞지 않습니다.
    source 를 붙여 절대 경로로 만든 뒤 대조합니다.
    """
    tree = ET.parse(coverage_xml)  # noqa: S314 - 자체 생성 산출물 (모듈 상단 사유 참조)
    covered = 0
    total = 0

    sources = [(s.text or "").replace("\\", "/").rstrip("/") for s in tree.iter("source")]

    for cls in tree.iter("class"):
        filename = (cls.get("filename") or "").replace("\\", "/")
        candidates = [filename, *(f"{src}/{filename}" for src in sources)]
        if not any(prefix in candidate for candidate in candidates):
            continue
        for line in cls.iter("line"):
            # 분기 전용 항목은 줄 수 계산에서 제외
            if line.get("number") is None:
                continue
            total += 1
            if int(line.get("hits") or 0) > 0:
                covered += 1

    return covered, total


def main() -> int:
    parser = argparse.ArgumentParser(description="모듈 단위 커버리지 임계값 검사")
    parser.add_argument("--module", required=True, help="예: phc.identity")
    parser.add_argument("--min", type=float, required=True, help="최소 커버리지 퍼센트")
    parser.add_argument("--xml", default="coverage.xml", help="coverage XML 경로")
    args = parser.parse_args()

    coverage_xml = Path(args.xml)
    if not coverage_xml.exists():
        print(f"[실패] 커버리지 리포트를 찾을 수 없습니다: {coverage_xml}", file=sys.stderr)
        return 2

    prefix = module_to_path_prefix(args.module)
    covered, total = measure(coverage_xml, prefix)

    if total == 0:
        # 모듈에 측정 대상이 없다는 것은 설정이 잘못되었다는 뜻입니다.
        # 조용히 통과시키면 커버리지 게이트가 무력화됩니다.
        print(
            f"[실패] '{args.module}' 에서 측정 가능한 줄을 찾지 못했습니다. "
            f"모듈 경로 또는 커버리지 설정을 확인하십시오.",
            file=sys.stderr,
        )
        return 2

    percent = covered / total * 100
    verdict = "통과" if percent >= args.min else "실패"
    print(f"[{verdict}] {args.module}: {percent:.1f}% ({covered}/{total}) — 기준 {args.min}%")

    return 0 if percent >= args.min else 1


if __name__ == "__main__":
    raise SystemExit(main())
