from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evals.runtime_fixtures import PILOT_CASES, materialize_fixture


class RuntimeFixtureTests(unittest.TestCase):
    def test_every_pilot_has_seed_prompt_and_is_reset_by_fresh_materialization(self) -> None:
        with TemporaryDirectory() as temp:
            for case in PILOT_CASES:
                with self.subTest(case=case):
                    first = Path(temp) / case / "first"
                    second = Path(temp) / case / "second"
                    fixture = materialize_fixture(case, first, condition="baseline")
                    other = materialize_fixture(case, second, condition="baseline")
                    self.assertEqual(fixture.prompt, other.prompt)
                    self.assertTrue((first / ".git").is_dir())
                    self.assertEqual(fixture.initial_files, other.initial_files)
                    for relative, content in fixture.initial_files:
                        self.assertEqual(content, (first / relative).read_text())
                    self.assertFalse((first / ".harness").exists())

    def test_harness_keeps_same_product_but_adds_actual_guidance_and_checks(self) -> None:
        with TemporaryDirectory() as temp:
            baseline = materialize_fixture("bug-fix", Path(temp) / "base", condition="baseline")
            harness = materialize_fixture("bug-fix", Path(temp) / "harness", condition="harness")
            self.assertEqual(baseline.initial_files, harness.initial_files)
            self.assertEqual(baseline.prompt, harness.prompt)
            self.assertTrue((harness.root / "AGENTS.md").is_file())
            self.assertTrue((harness.root / "scripts/harness_evidence.py").is_file())
            self.assertTrue((harness.root / ".harness/config.toml").is_file())

    def test_invalid_inputs_and_reusing_existing_workspace_fail_without_overwrite(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp) / "fixture"
            materialize_fixture("documentation", root, condition="baseline")
            before = (root / "README.md").read_bytes()
            for case, condition in (("../escape", "baseline"), ("documentation", "other"), ("documentation", "baseline")):
                with self.subTest(case=case, condition=condition), self.assertRaises(ValueError):
                    materialize_fixture(case, root, condition=condition)
                self.assertEqual(before, (root / "README.md").read_bytes())
            link = Path(temp) / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                materialize_fixture("documentation", link, condition="baseline")

    def test_reserved_variant_changes_seed_and_requires_separate_identity(self) -> None:
        with TemporaryDirectory() as temp:
            pilot = materialize_fixture("bug-fix", Path(temp) / "pilot", condition="baseline", variant="pilot")
            unseen = materialize_fixture("bug-fix", Path(temp) / "unseen", condition="baseline", variant="unseen")
            self.assertNotEqual(pilot.initial_files, unseen.initial_files)
            self.assertNotEqual(pilot.fixture_sha256, unseen.fixture_sha256)


if __name__ == "__main__":
    unittest.main()
