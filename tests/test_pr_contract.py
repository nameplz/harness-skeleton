from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_pr_contract import check_event_file  # noqa: E402


VALID_BODY = """
## 작업 목적
목적

## 변경 범위
범위

## 테스트 내용
테스트

## 검증 결과
검증

## 영향 범위
영향

## 롤백 방법
롤백
"""


class PrContractTests(unittest.TestCase):
    def write_event(self, root: Path, title: str, body: str) -> Path:
        event = root / "event.json"
        event.write_text(
            json.dumps({"pull_request": {"title": title, "body": body}}),
            encoding="utf-8",
        )
        return event

    def test_valid_pr_contract_passes(self) -> None:
        with TemporaryDirectory() as temp:
            event = self.write_event(Path(temp), "feat: 하네스 검증 추가", VALID_BODY)

            errors = check_event_file(event)

            self.assertEqual([], errors)

    def test_missing_required_body_section_fails(self) -> None:
        with TemporaryDirectory() as temp:
            event = self.write_event(Path(temp), "fix: PR 검증 수정", "## 작업 목적\n목적\n")

            errors = check_event_file(event)

            self.assertTrue(any("변경 범위" in error for error in errors))

    def test_malicious_title_is_data_only(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "marker"
            event = self.write_event(root, f"fix: $(touch {marker})", VALID_BODY)

            errors = check_event_file(event)

            self.assertEqual([], errors)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
