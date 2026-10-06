from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from scripts.eval_harness import main


ROOT = Path(__file__).resolve().parents[1]


class HarnessRiskEvalTests(unittest.TestCase):
    def test_representative_risk_cases_pass(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["--fixture", str(ROOT / "evals/risk-cases.json")])

        self.assertEqual(0, exit_code, output.getvalue())
        self.assertIn("cases passed", output.getvalue())

    def test_expected_mismatch_returns_nonzero(self) -> None:
        fixture = {
            "cases": [
                {
                    "name": "wrong expectation",
                    "paths": ["src/app.py"],
                    "diff": "+return value",
                    "expected": {"level": "T3", "code_review": True, "security_review": True},
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cases.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(1, exit_code)
        self.assertIn("wrong expectation", output.getvalue())

    def test_malformed_fixture_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cases.json"
            path.write_text('{"cases": [{"name": "missing fields"}]}', encoding="utf-8")
            errors = StringIO()

            with redirect_stderr(errors):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(2, exit_code)
        self.assertIn("invalid risk eval fixture", errors.getvalue())

    def test_unhashable_expected_level_fails_closed(self) -> None:
        fixture = {
            "cases": [
                {
                    "name": "invalid expected level",
                    "paths": ["src/app.py"],
                    "diff": "+change",
                    "expected": {"level": [], "code_review": False, "security_review": False},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cases.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            errors = StringIO()

            with redirect_stderr(errors):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(2, exit_code)
        self.assertIn("invalid risk eval fixture", errors.getvalue())

    def test_non_regular_fixture_fails_closed(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("named pipes are not available on this platform")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cases.fifo"
            os.mkfifo(path)
            errors = StringIO()

            with redirect_stderr(errors):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(2, exit_code)
        self.assertIn("invalid risk eval fixture", errors.getvalue())

    def test_symlink_fixture_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target.json"
            target.write_text((ROOT / "evals/risk-cases.json").read_text(encoding="utf-8"), encoding="utf-8")
            path = Path(temp) / "cases.json"
            path.symlink_to(target)
            errors = StringIO()

            with redirect_stderr(errors):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(2, exit_code)
        self.assertIn("invalid risk eval fixture", errors.getvalue())

    def test_control_characters_in_fixture_name_fail_closed(self) -> None:
        fixture = {
            "cases": [
                {
                    "name": "unsafe\x1bname",
                    "paths": ["src/app.py"],
                    "diff": "+change",
                    "expected": {"level": "T1", "code_review": False, "security_review": False},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cases.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            errors = StringIO()

            with redirect_stderr(errors):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(2, exit_code)
        self.assertIn("invalid risk eval fixture", errors.getvalue())

    def test_duplicate_fixture_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cases.json"
            path.write_text('{"cases": [], "cases": []}', encoding="utf-8")
            errors = StringIO()

            with redirect_stderr(errors):
                exit_code = main(["--fixture", str(path)])

        self.assertEqual(2, exit_code)
        self.assertIn("duplicate fixture field", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
