from __future__ import annotations

from pathlib import Path
import re
import json
import shutil
import subprocess
import sys
import tomllib
import unittest
from tempfile import TemporaryDirectory

from tests import test_harness as baseline


ROOT = Path(__file__).resolve().parents[2]


class AgentDocsTests(unittest.TestCase):
    def test_agents_file_is_a_short_router_to_live_sources(self) -> None:
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        self.assertLessEqual(len(agents.splitlines()), 100)
        for relative in (
            "docs/ARCHITECTURE.md",
            "docs/ADR.md",
            ".agents/skills/harness/SKILL.md",
        ):
            self.assertIn(relative, agents)
            self.assertTrue((ROOT / relative).is_file(), relative)
        self.assertIn("only when modifying Harness itself", agents)
        self.assertEqual(["# Project", "## Commands", "## Layout", "## Code style", "## Boundaries",
                          "## Validation ladder (local)", "## References"],
                         re.findall(r"^#{1,2} .+", agents, re.M))
        for placeholder in ("{one-line description}", "{setup command}", "{run command}", "{snippet:"):
            self.assertIn(placeholder, agents)
        self.assertIn("```python", agents)
        self.assertIn("return bool(name.strip())", agents)
        for boundary in ("Always:", "Ask first:", "Never commit secrets", "Never bypass the commit gate",
                         "--no-verify", "adding dependencies"):
            self.assertIn(boundary, agents)
        self.assertNotIn("harness.py status", agents)
        self.assertNotRegex(agents, r"(?i)codex|claude|you are a")
        for command in ("check --quick", "check --full", "gate", "install-gate", "risk", "doctor", "selftest"):
            self.assertIn(f"python scripts/harness.py {command}", agents)
        for contract in ("2–5", "1–3", "exit code", "unverified", "weaken tests"):
            self.assertIn(contract, agents)

    def test_wp07_ac2_empty_skeleton_doctor_and_bootstrap(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp) / "skeleton"
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".codex", ".claude"))
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            def run(*arguments: str) -> tuple[int, dict]:
                result = subprocess.run([sys.executable, "-I", str(root / "scripts/harness.py"),
                                         "doctor", *arguments], cwd=root, capture_output=True, text=True)
                return result.returncode, json.loads(result.stdout)
            code, regular = run()
            self.assertEqual(1, code)
            self.assertFalse(regular["ok"])
            self.assertIn("unresolved placeholder: AGENTS.md", regular["errors"])
            code, bootstrap = run("--bootstrap")
            self.assertEqual(0, code, bootstrap)
            self.assertTrue(bootstrap["ok"])
            self.assertEqual("unconfigured", bootstrap["status"])
            (root / "AGENTS.md").unlink()
            code, missing = run("--bootstrap")
            self.assertEqual(1, code)
            self.assertIn("AGENTS.md", missing["errors"])
            self.assertIn("could not read project guide: AGENTS.md", missing["errors"])

    def test_wp07_ac3_templates_are_optional_and_not_scanned(self) -> None:
        from scripts.harness_doctor import REQUIRED_PROJECT_FILES, REQUIRED_DOC_SCAN_PATHS, _doctor_doc_errors
        for name in ("PRD.md", "UI_GUIDE.md"):
            self.assertFalse((ROOT / "docs" / name).exists())
            template = ROOT / "docs/templates" / name
            self.assertTrue(template.is_file())
            self.assertRegex(template.read_text(), r"\{[^{}\n]+\}")
            self.assertNotIn(f"docs/templates/{name}", REQUIRED_PROJECT_FILES)
            self.assertNotIn(f"docs/templates/{name}", REQUIRED_DOC_SCAN_PATHS)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in REQUIRED_DOC_SCAN_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Configured guide.\n")
            shutil.copytree(ROOT / "docs/templates", root / "docs/templates")
            self.assertEqual([], _doctor_doc_errors(root))
            shutil.rmtree(root / "docs/templates")
            self.assertEqual([], _doctor_doc_errors(root))

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
        self.assertIn("configured checks and required reviews pass", skill)
        self.assertIn("unrelated changes", skill)
        self.assertIn("honor explicit no-commit instructions", skill)
        self.assertIn("remote work only when requested by the user", skill)
        for command in ("install-gate", "check --full", "gate"):
            self.assertIn(f"python scripts/harness.py {command}", skill)
        self.assertIn("before committing to catch failures early", skill)
        self.assertIn("current head, diff, and config", skill)
        self.assertIn("never push, create a pr, or merge without a user request", agents)

    def test_agent_docs_fit_budgets_and_have_no_retired_workflows(self) -> None:
        paths = [ROOT / "AGENTS.md", ROOT / "docs/ARCHITECTURE.md"]
        paths.extend(sorted((ROOT / ".agents/skills").glob("**/SKILL.md")))
        contents = {path: path.read_text(encoding="utf-8") for path in paths}
        self.assertLessEqual(sum(len(text.split()) for text in contents.values()), 2000)
        self.assertLessEqual(len(contents[ROOT / ".agents/skills/harness/SKILL.md"].split()), 650)
        self.assertLessEqual(len(contents[ROOT / "docs/ARCHITECTURE.md"].split()), 600)
        retired = r"issue-first|pull request|verify_ci|ci-setup|pr-workflow|github actions"
        for path in (ROOT / "AGENTS.md", *sorted((ROOT / ".agents").rglob("*.md")),
                     *sorted((ROOT / "docs").rglob("*.md"))):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                if path.name == "ADR.md":
                    text = "\n".join(line for line in text.splitlines() if "Superseded by ADR-018" not in line)
                self.assertIsNone(re.search(retired, text, re.I))
        self.assertFalse((ROOT / "gitignore.txt").exists())
        self.assertFalse((ROOT / "deploy").exists())

    def test_profile_setup_and_local_architecture_are_documented(self) -> None:
        skill = (ROOT / ".agents/skills/harness/SKILL.md").read_text(encoding="utf-8")
        setup = skill.split("## Validation profile setup\n", 1)[1].split("\n## ", 1)[0]
        for required in (
            "unconfigured", "multiple files", "runtime versions", "lockfiles",
            "real test files and runners", "lint/type/build", "package scripts",
            "checks.quick", "checks.full", "argv arrays", "shell=False",
            "dependency installation", "credentials", "Never invent", "empty profile is not a pass",
            "check --quick", "check --full", "scripts/harness.py doctor", "T2 review",
            "Do not put long-running resident processes", "npm run watch", "checks must terminate",
        ):
            self.assertIn(required, setup)
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        for required in ("Principle 7", "Principle 8", "agent mistakes", "Failure prevented",
                         "stop_hook_active", "unknown/failed risk", "environment allowlist"):
            self.assertIn(required, architecture)
        integration = "CI를 쓰려면 원하는 workflow에서 `python -I scripts/harness.py check --full`을 호출하면 된다."
        self.assertEqual(architecture.split("## 4.4 Optional remote integration\n", 1)[1].strip(), integration)

    def test_decision_history_and_task_template_match_local_evidence_contract(self) -> None:
        adr = (ROOT / "docs/ADR.md").read_text(encoding="utf-8")
        for number in ("013", "016", "017"):
            section = adr.split(f"### ADR-{number}:", 1)[1].split("\n### ADR-", 1)[0]
            body = section.split("\n", 1)[1].strip().splitlines()
            self.assertEqual(1, len(body))
            self.assertIn("Superseded by ADR-018", body[0])
        decision = adr.split("### ADR-018:", 1)[1]
        self.assertLessEqual(len(decision.split()), 400)
        for required in ("§2.1", "principles 7–8", "T0", "T1", "T2", "T3", "N1", "N2", "Excluded"):
            self.assertIn(required, decision)
        template = (ROOT / ".harness/task-template.md").read_text(encoding="utf-8")
        self.assertTrue(template.startswith("# Acceptance\n"))
        self.assertGreaterEqual(template.count("- [ ] Criterion:"), 2)
        self.assertIn("Evidence (command, exit code, 1–3 key output lines; otherwise unverified)", template)
        self.assertIn("Issue link (if used)", template)
        self.assertIn("PR/CI state (if used)", template)

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
