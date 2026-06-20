from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.harness_validation import (  # noqa: E402
    HarnessValidationError,
    active_profiles,
    detect_profiles,
    load_validation_config,
    validate_project,
)


class HarnessValidationTests(unittest.TestCase):
    def write(self, root: Path, relative: str, text: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_skeleton_mode_allows_placeholders_without_config(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root, "docs/PRD.md", "# PRD: {프로젝트명}\n")
            self.write(root, "docs/ARCHITECTURE.md", "# 아키텍처\n{패턴}\n")
            self.write(root, "docs/ADR.md", "# ADR\n{결정}\n")

            result = validate_project(root=root, strict=False, config_path=None, run_commands=False)

            self.assertEqual([], result.errors)

    def test_strict_mode_rejects_placeholders(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root, "docs/PRD.md", "# PRD: {프로젝트명}\n")
            self.write(root, "docs/ARCHITECTURE.md", "# 아키텍처\n")
            self.write(root, "docs/ADR.md", "# ADR\n")

            result = validate_project(root=root, strict=True, config_path=None, run_commands=False)

            self.assertTrue(any("placeholder" in error for error in result.errors))

    def test_configured_project_rejects_placeholders(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root, "docs/PRD.md", "# PRD: {프로젝트명}\n")
            self.write(root, "docs/ARCHITECTURE.md", "# 아키텍처\n")
            self.write(root, "docs/ADR.md", "# ADR\n")
            self.write(
                root,
                ".harness/validation.json",
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "mode": "language-neutral",
                        "profiles": [],
                        "commands": [],
                        "checks": {"docs": True, "deploy": True, "phase": True},
                    }
                ),
            )

            result = validate_project(root=root, strict=False, config_path=None, run_commands=False)

            self.assertTrue(any("placeholder" in error for error in result.errors))

    def test_unsafe_command_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(
                root,
                ".harness/validation.json",
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "mode": "language-neutral",
                        "profiles": [],
                        "commands": [
                            {
                                "name": "install",
                                "command": ["npm", "install"],
                                "reason": "unsafe in validation",
                            }
                        ],
                        "checks": {"docs": False, "deploy": False, "phase": False},
                    }
                ),
            )

            with self.assertRaises(HarnessValidationError):
                load_validation_config(root / ".harness/validation.json")

    def test_shell_string_command_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(
                root,
                ".harness/validation.json",
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "mode": "language-neutral",
                        "profiles": [],
                        "commands": [
                            {
                                "name": "bad",
                                "command": "npm test",
                                "reason": "must be argv",
                            }
                        ],
                        "checks": {"docs": False, "deploy": False, "phase": False},
                    }
                ),
            )

            with self.assertRaises(HarnessValidationError):
                load_validation_config(root / ".harness/validation.json")

    def test_deploy_files_outside_deploy_fail(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root, "docs/PRD.md", "# PRD\n")
            self.write(root, "docs/ARCHITECTURE.md", "# Arch\n")
            self.write(root, "docs/ADR.md", "# ADR\n")
            self.write(root, "vercel.json", "{}\n")

            result = validate_project(root=root, strict=False, config_path=None, run_commands=False)

            self.assertTrue(any("deploy/" in error for error in result.errors))

    def test_profile_detection_uses_evidence_or_explicit_config(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual([], detect_profiles(root))

            self.write(root, "package.json", "{}\n")
            self.assertEqual(["node"], detect_profiles(root))
            self.assertEqual(["node", "python"], active_profiles(root, ["python"]))


if __name__ == "__main__":
    unittest.main()
