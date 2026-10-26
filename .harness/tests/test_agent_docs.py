from __future__ import annotations

from pathlib import Path
import tomllib
import unittest
from tempfile import TemporaryDirectory

from tests import test_harness as baseline


ROOT = Path(__file__).resolve().parents[2]


class AgentDocsTests(unittest.TestCase):
    def test_agents_file_is_a_short_router_to_live_sources(self) -> None:
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        self.assertLessEqual(len(agents.splitlines()), 40)
        for relative in (
            "docs/ARCHITECTURE.md",
            "docs/ADR.md",
            ".agents/skills/harness/SKILL.md",
        ):
            self.assertIn(relative, agents)
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_one_harness_skill_defines_risk_routing_and_deterministic_validation(self) -> None:
        skill = ROOT / ".agents/skills/harness/SKILL.md"
        self.assertTrue(skill.is_file())
        content = skill.read_text(encoding="utf-8")

        for level in ("T0", "T1", "T2", "T3"):
            self.assertIn(level, content)
        self.assertIn("test-review", content)
        self.assertIn("security", content.lower())
        self.assertIn("one implementation writer", content.lower())
        self.assertIn("scripts/harness.py", content)
        for field in ("status", "summary", "findings", "evidence", "recommendation", "path:line"):
            self.assertIn(field, content)
        self.assertFalse((ROOT / ".agents/skills/harness-workflow/SKILL.md").exists())
        self.assertFalse((ROOT / ".agents/skills/harness-review/SKILL.md").exists())

    def test_workflow_commits_each_verified_task_unit(self) -> None:
        skill = (ROOT / ".agents/skills/harness/SKILL.md").read_text(encoding="utf-8").lower()
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()

        self.assertIn("commit each completed task separately", skill)
        self.assertIn("configured checks and required reviews pass", agents)
        self.assertIn("unrelated changes", skill)
        self.assertIn("wait for generated ci checks to pass", agents)
        self.assertIn("never merge unless asked", agents)

    def test_codex_roles_exist_and_reviewers_are_read_only(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        agents = config["agents"]

        self.assertTrue(config["features"]["multi_agent"])
        self.assertTrue(config["features"]["hooks"])
        self.assertTrue(agents["enabled"])
        self.assertNotIn("max_concurrent_threads_per_session", agents)
        self.assertEqual({"reviewer", "security_reviewer"}, {key for key in agents if isinstance(agents[key], dict)})
        skill = (ROOT / ".agents/skills/harness/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("`reviewer`", skill)
        self.assertIn("`security_reviewer`", skill)
        for role in ("reviewer", "security_reviewer"):
            with self.subTest(role=role):
                role_config_path = ROOT / ".codex" / agents[role]["config_file"]
                role_config = tomllib.loads(role_config_path.read_text(encoding="utf-8"))
                self.assertEqual("read-only", role_config["sandbox_mode"])
                instructions = role_config["developer_instructions"].lower()
                for required in (
                    "read-only", "do not send messages", "modify remote state",
                    "including push or pr creation", "edit files, or commit",
                    "review only the requested change",
                    "report only requirement gaps, incorrect behavior, regressions, missing tests",
                    "whether test_weakening signals are justified",
                    "do not report style, personal preferences, or hypothetical cases",
                    "each finding must include a repository path:line reference and a concrete failure scenario",
                    "explicitly report no findings",
                ):
                    self.assertIn(required, instructions)
                self.assertNotIn("contract and architecture drift", instructions)
                if role == "security_reviewer":
                    self.assertIn("limited to changed trust boundaries", instructions)
                    for boundary in (
                        "authorization", "input validation", "path confinement",
                        "subprocess and shell use", "credentials", "network access",
                        "permissions", "data exposure", "failure handling",
                    ):
                        self.assertIn(boundary, instructions)
                self.assertNotIn("model", role_config)

    def test_skeleton_does_not_assume_a_project_validation_stack(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            baseline.HarnessCheckTests.write_config(self, root, [], [])
            config = tomllib.loads((root / ".harness/config.toml").read_text(encoding="utf-8"))
            for profile in ("quick", "full"):
                with self.subTest(profile=profile):
                    self.assertEqual([], config["checks"][profile])
            self.assertFalse((root / ".github/workflows/harness-ci.yml").exists())
            self.assertFalse((root / ".github/workflows/project-ci.yml").exists())


if __name__ == "__main__":
    unittest.main()
