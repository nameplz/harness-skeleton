import ast
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import tomllib
import unittest

from scripts.harness import doctor
from scripts.harness_doctor import _doctor_doc_errors
from tests.test_harness_doctor import _write_doctor_files

ROOT = Path(__file__).resolve().parents[2]


class DocsConsistencyTests(unittest.TestCase):
    def test_wp11_ac2_architecture_states_contracts_bypasses_and_removal_conditions(self):
        text = (ROOT / "docs/ARCHITECTURE.md").read_text()
        for phrase in ("## Minimum verification", "Assumed model weakness", "Removal condition",
                       "--no-verify", "core.hooksPath", "forged", "non-commit", "untrusted input", "external writes"):
            self.assertIn(phrase.lower(), text.lower())
        for number in range(1, 7):
            self.assertRegex(text, rf"\| MV-{number} \|")

    def test_wp11_ac3_doctor_reports_broken_relative_agents_link(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            subprocess.run(["git", "init", "-q", str(root)], capture_output=True, check=True)
            self.assertTrue(doctor(root, bootstrap=True)["ok"])
            (root / "AGENTS.md").write_text("[Missing guide](docs/missing.md)\n")
            report = doctor(root, bootstrap=True)
            self.assertFalse(report["ok"])
            self.assertTrue(any("AGENTS.md" in error and "docs/missing.md" in error for error in report["errors"]))

    def test_wp11_ac3_optional_claude_and_skill_links_resolve_from_their_document(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            for name in ("CLAUDE.md", ".agents/skills/harness/SKILL.md"):
                with self.subTest(document=name):
                    path = root / name
                    path.write_text("[Missing](missing.md)\n")
                    self.assertTrue(any(name in error and "missing.md" in error for error in _doctor_doc_errors(root)))
                    (path.parent / "local guide.md").write_text("present\n")
                    adr_path = "docs/ADR.md" if name == "CLAUDE.md" else "../../../docs/ADR.md"
                    path.write_text('[Local](<local%20guide.md#heading>)\n' + f'[ADR]({adr_path}#decision)\n')
                    self.assertEqual([], _doctor_doc_errors(root))

    def test_wp11_ac3_links_ignore_remote_urls_anchors_and_code_examples(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            agents = root / "AGENTS.md"
            agents.write_text('[Web](https://example.test/missing) [Email](mailto:a@example.test) [Anchor](#local)\n'
                              '`[Example](missing-inline.md)`\n```md\n[Example](missing-fenced.md)\n```\n')
            self.assertEqual([], _doctor_doc_errors(root))
            agents.write_text('[guide][ref]\n[ref]: docs/missing.md\n')
            self.assertTrue(any("docs/missing.md" in error for error in _doctor_doc_errors(root)))

    def test_wp11_ac4_mv6_each_minimum_contract_has_a_named_test(self):
        covered = set()
        for path in (ROOT / ".harness/tests").glob("test_*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                    text = node.name + " " + (ast.get_docstring(node) or "")
                    covered.update(re.findall(r"mv[-_]?([1-5])(?!\d)", text, re.I))
        self.assertEqual(set("12345"), covered)

    def test_wp11_ac5_guidance_matches_adapters_and_keeps_timeouts(self):
        skill = (ROOT / ".agents/skills/harness/SKILL.md").read_text()
        self.assertIn("instructions/control files", skill)
        self.assertIn("status --json", skill)
        self.assertIn("stdout", skill)
        self.assertLessEqual(len(skill.split()), 650)
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text()
        self.assertIn("scripts/hooks/agent_hook.py", architecture)
        self.assertNotIn(".codex/hooks/harness_hook.py", architecture)
        adr = (ROOT / "docs/ADR.md").read_text()
        self.assertIn("ADR-019", adr)
        for phrase in ("DEC-01", "DEC-02", "DEC-03", "DEC-04", "DEC-05", "DEC-06", "DEC-07", "DEC-12", "default"):
            self.assertIn(phrase, adr)
        codex = tomllib.loads((ROOT / ".codex/config.toml").read_text())
        claude = json.loads((ROOT / ".claude/settings.json").read_text())
        for event, timeout in (("PreToolUse", 960), ("Stop", 180)):
            self.assertEqual(timeout, codex["hooks"][event][0]["hooks"][0]["timeout"])
            self.assertEqual(timeout, claude["hooks"][event][0]["hooks"][0]["timeout"])
        self.assertNotIn("commit validation", codex["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"])
