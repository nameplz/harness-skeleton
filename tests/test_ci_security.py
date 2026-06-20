from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_ci_security import check_security_policy  # noqa: E402


PINNED_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


class CiSecurityTests(unittest.TestCase):
    def write_workflow(self, root: Path, body: str) -> None:
        workflow = root / ".github/workflows/harness-ci.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text(body, encoding="utf-8")

    def write_event(self, root: Path, filenames: list[str] | None = None) -> Path:
        event = root / "event.json"
        event.write_text(
            json.dumps({"pull_request": {"changed_files": [{"filename": name} for name in filenames or []]}}),
            encoding="utf-8",
        )
        return event

    def test_unpinned_external_action_fails(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n")
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("full commit SHA" in error for error in errors))

    def test_full_sha_pinned_action_passes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertEqual([], errors)

    def test_forbidden_workflow_features_fail(self) -> None:
        cases = [
            "on: pull_request_target\n",
            "permissions:\n  contents: write\n",
            "permissions: write-all\n",
            "permissions:\n  id-token: write\n",
            "runs-on: self-hosted\n",
            "run: echo ${{ secrets.TOKEN }}\n",
        ]
        for body in cases:
            with self.subTest(body=body), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_workflow(root, body)
                event = self.write_event(root)

                errors = check_security_policy(root=root, event_path=event)

                self.assertNotEqual([], errors)

    def test_security_sensitive_pr_changes_fail(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root, [".harness/ci.json"])

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("security-sensitive" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
