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
Refs #123

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

    def test_empty_or_comment_only_sections_fail(self) -> None:
        for purpose in ("", "<!-- explain the purpose -->"):
            with self.subTest(purpose=purpose), TemporaryDirectory() as temp:
                body = VALID_BODY.replace("목적\nRefs #123", purpose + "\nRefs #123")
                body = body.replace("## 변경 범위\n범위", "## 변경 범위\n<!-- fill in -->")
                errors = check_event_file(self.write_event(Path(temp), "fix: body", body))
                self.assertTrue(any("변경 범위" in error for error in errors))

    def test_issue_reference_is_required_and_cannot_be_in_a_comment_or_code_block(self) -> None:
        for reference in ("", "<!-- Refs #123 -->", "```\nRefs #123\n```", "Refs #0", "`Refs #123`", "    Refs #123"):
            with self.subTest(reference=reference), TemporaryDirectory() as temp:
                body = VALID_BODY.replace("Refs #123", reference)
                errors = check_event_file(self.write_event(Path(temp), "fix: body", body))
                self.assertTrue(any("issue" in error for error in errors))

    def test_issue_urls_and_case_insensitive_closing_keywords_pass(self) -> None:
        for reference in ("closes #42", "Refs https://github.com/nameplz/harness-skeleton/issues/42"):
            with self.subTest(reference=reference), TemporaryDirectory() as temp:
                body = VALID_BODY.replace("Refs #123", reference)
                self.assertEqual([], check_event_file(self.write_event(Path(temp), "fix: body", body)))

    def test_headings_inside_code_fences_do_not_satisfy_the_contract(self) -> None:
        with TemporaryDirectory() as temp:
            body = "```markdown\n" + VALID_BODY + "\n```\nRefs #123\n"
            errors = check_event_file(self.write_event(Path(temp), "fix: body", body))
            self.assertTrue(any("작업 목적" in error for error in errors))

    def test_indented_code_headings_do_not_satisfy_the_contract(self) -> None:
        with TemporaryDirectory() as temp:
            body = "\n".join("    " + line for line in VALID_BODY.splitlines()) + "\nRefs #123\n"
            errors = check_event_file(self.write_event(Path(temp), "fix: body", body))
            self.assertTrue(any("작업 목적" in error for error in errors))

    def test_nested_headings_without_description_do_not_satisfy_the_contract(self) -> None:
        from scripts.check_pr_contract import REQUIRED_SECTIONS

        with TemporaryDirectory() as temp:
            body = "\n".join(f"## {section}\n### placeholder" for section in REQUIRED_SECTIONS) + "\nRefs #123\n"
            errors = check_event_file(self.write_event(Path(temp), "fix: body", body))
            self.assertTrue(any("작업 목적" in error for error in errors))
            described = body.replace("### placeholder", "### Details\nCompleted change.")
            self.assertEqual([], check_event_file(self.write_event(Path(temp), "fix: body", described)))

    def test_removing_hidden_markup_cannot_create_a_heading(self) -> None:
        for prefix in ("`prefix` ", "<!--prefix--> ", "`prefix\nsuffix` ", "<!--prefix\nsuffix--> "):
            with self.subTest(prefix=prefix), TemporaryDirectory() as temp:
                body = VALID_BODY.replace("## ", prefix + "## ")
                errors = check_event_file(self.write_event(Path(temp), "fix: body", body))
                self.assertTrue(any("작업 목적" in error for error in errors))

    def test_filled_repository_template_passes_and_unfilled_template_fails(self) -> None:
        import re

        template = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        with TemporaryDirectory() as temp:
            event = self.write_event(Path(temp), "fix: template", template)
            self.assertTrue(check_event_file(event))
            filled = re.sub(r"<!--.*?-->", "Completed and verified.", template, flags=re.DOTALL)
            event = self.write_event(Path(temp), "fix: template", filled + "\nRefs #123\n")
            self.assertEqual([], check_event_file(event))


if __name__ == "__main__":
    unittest.main()
