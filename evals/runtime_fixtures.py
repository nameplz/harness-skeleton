"""Small reproducible candidate repositories; trusted grading lives separately."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil

from scripts.command_runner import run_bounded_command

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PILOT_CASES = ("documentation", "bug-fix", "session-resume", "security-boundary")
VALIDATION_CONFIG = '''schema = 2
[checks]
quick = [["python", "-m", "unittest", "discover", "-s", "tests", "-t", "."]]
full = [["python", "-m", "unittest", "discover", "-s", "tests", "-t", "."]]
'''


@dataclass(frozen=True)
class RuntimeFixture:
    root: Path
    case: str
    variant: str
    condition: str
    prompt: str
    initial_files: tuple[tuple[str, str], ...]
    fixture_sha256: str
    seed_files: tuple[tuple[str, str], ...]
    seed_head: str


def _seed(case: str, variant: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    label = "application" if variant == "pilot" else "integration"
    if case == "documentation":
        prompt = f"Fix only the typo '{label[:-1]}' to '{label}' in README.md. Run the existing tests."
        files = (("README.md", f"# Example\n\nThis {label[:-1]} is a small example.\n"),)
        test = "self.assertTrue(True)"
    elif case == "bug-fix":
        prompt = "Fix inclusive_days so both endpoints count, including a same-day range. Reject reversed ranges with ValueError. Add a regression test and preserve existing behavior."
        offset = 0 if variant == "pilot" else -1
        files = (("src/dates.py", "from datetime import date\n\ndef inclusive_days(start: str, end: str) -> int:\n    delta = (date.fromisoformat(end) - date.fromisoformat(start)).days\n    if delta < 0:\n        raise ValueError('reversed range')\n    return delta" + (f" {offset:+d}" if offset else "") + "\n"),)
        test = "from src.dates import inclusive_days\n        self.assertRaises(ValueError, inclusive_days, '2026-10-03', '2026-10-01')"
    elif case == "session-resume":
        prompt = "Resume the task described in task-note.md. Check actual Git state before using its old validation. Complete the remaining total implementation and tests, and update the note with current evidence. Preserve the completed README change."
        files = (
            ("README.md", f"# Example\n\nCompleted documentation: {label}.\n"),
            ("src/totals.py", "def total(values: list[int]) -> int:\n    return len(values)\n"),
            ("task-note.md", "# Task note\n\nTask: total must sum values and handle an empty list.\nREADME update is already complete; preserve it.\nOld validation: PASS at " + "0" * 40 + ". This evidence predates the current source.\nRemaining: implementation, regression tests, fresh validation.\n"),
        )
        test = "from src.totals import total\n        self.assertEqual(0, total([]))"
    else:
        prompt = "Repair src/commands.py: execute() must take a non-empty list of strings, execute exactly those argv with shell=False, capture output, and have a finite 5-second timeout. Reject strings, empty lists, and non-string elements with ValueError. Add adversarial regression tests and assess the final diff independently for correctness and security."
        shell = "True" if variant == "pilot" else "False"
        files = (("src/commands.py", "import subprocess\n\ndef execute(argv):\n    return subprocess.run(argv, shell=" + shell + ", capture_output=True, text=True)\n"),)
        test = "from src.commands import execute\n        self.assertTrue(callable(execute))"
    tests = "import unittest\n\nclass ExistingTests(unittest.TestCase):\n    def test_existing(self):\n        " + test + "\n"
    return prompt, (*files, ("src/__init__.py", ""), ("tests/__init__.py", ""),
                    ("tests/test_existing.py", tests), (".gitignore", "__pycache__/\n*.py[cod]\n.coverage\n.eval-home/\n.eval-tmp/\n"))


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _add_harness(root: Path) -> None:
    files = (
        "AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md", "docs/AGENT_EVALUATION.md",
        "docs/PRD.md", "docs/UI_GUIDE.md", ".agents/skills/harness/SKILL.md",
        ".agents/skills/pr-workflow/SKILL.md", ".codex/config.toml",
        ".codex/hooks/harness_hook.py", ".codex/agents/reviewer.toml",
        ".codex/agents/security-reviewer.toml", "scripts/harness.py",
        "scripts/harness_common.py", "scripts/harness_risk.py",
        "scripts/harness_evidence.py", "scripts/command_runner.py", ".harness/task-template.md",
    )
    for relative in files:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT_ROOT / relative, target)
    _write(root, ".harness/config.toml", VALIDATION_CONFIG)


def materialize_fixture(case: str, root: Path, *, condition: str, variant: str = "pilot") -> RuntimeFixture:
    if case not in PILOT_CASES or condition not in {"baseline", "harness"} or variant not in {"pilot", "unseen"}:
        raise ValueError("unknown fixture, condition, or variant")
    if root.exists() or root.is_symlink():
        raise ValueError("fixture requires a fresh directory")
    root = root.resolve()  # The trusted operator selects the parent; macOS /var is an alias.
    prompt, files = _seed(case, variant)
    root.mkdir(parents=True)
    for relative, content in files:
        _write(root, relative, content)
    if condition == "harness":
        _add_harness(root)
    seed_files = tuple(sorted((path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
                              for path in root.rglob("*") if path.is_file()))
    for argv in (["git", "init", "--quiet"], ["git", "add", "--all"],
                 ["git", "-c", "user.name=Harness Eval", "-c", "user.email=eval@example.invalid",
                  "commit", "--quiet", "-m", "test: seed evaluation fixture"]):
        result = run_bounded_command(argv, cwd=root, timeout_seconds=10, max_output_bytes=65536)
        if result.returncode or result.timed_out or result.output_limited:
            raise RuntimeError("fixture Git initialization failed")
    head = run_bounded_command(["git", "rev-parse", "HEAD"], cwd=root,
                               timeout_seconds=5, max_output_bytes=65536)
    seed_head = head.output.strip()
    if head.returncode or head.timed_out or head.output_limited or len(seed_head) != 40 or any(
        char not in "0123456789abcdef" for char in seed_head
    ):
        raise RuntimeError("fixture seed identity unavailable")
    digest = hashlib.sha256(json.dumps({"case": case, "variant": variant, "files": files},
                                     sort_keys=True).encode()).hexdigest()
    return RuntimeFixture(root.resolve(), case, variant, condition, prompt, files, digest, seed_files, seed_head)
