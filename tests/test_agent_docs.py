from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


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

    def test_codex_roles_exist_and_reviewers_are_read_only(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        agents = config["agents"]

        self.assertTrue(config["features"]["multi_agent"])
        self.assertEqual(2, agents["max_concurrent_threads_per_session"])
        self.assertEqual({"reviewer", "security_reviewer"}, {key for key in agents if isinstance(agents[key], dict)})
        skill = (ROOT / ".agents/skills/harness/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("`reviewer`", skill)
        self.assertIn("`security_reviewer`", skill)
        for role in ("reviewer", "security_reviewer"):
            with self.subTest(role=role):
                role_config_path = ROOT / ".codex" / agents[role]["config_file"]
                role_config = tomllib.loads(role_config_path.read_text(encoding="utf-8"))
                self.assertEqual("read-only", role_config["sandbox_mode"])
                self.assertIn("read-only", role_config["developer_instructions"].lower())

    def test_validation_test_discovery_uses_project_root_as_top_level(self) -> None:
        config = tomllib.loads((ROOT / ".harness/config.toml").read_text(encoding="utf-8"))
        expected = ["python", "-m", "unittest", "discover", "-s", "tests", "-t", "."]

        for profile in ("quick", "full"):
            with self.subTest(profile=profile):
                self.assertIn(expected, config["checks"][profile])


if __name__ == "__main__":
    unittest.main()
