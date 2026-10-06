from __future__ import annotations

import json
import subprocess
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sys
import unittest
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.harness import HarnessError, load_config, main  # noqa: E402


class HarnessPathTests(unittest.TestCase):
    def test_config_symlink_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            config_dir = root / ".harness"
            config_dir.mkdir()
            external_config = Path(outside) / "config.toml"
            external_config.write_text(
                'schema = 2\n[checks]\nquick = [["true"]]\nfull = [["true"]]\n',
                encoding="utf-8",
            )
            (config_dir / "config.toml").symlink_to(external_config)

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_risk_root_scopes_git_changes_and_loads_nested_rules(self) -> None:
        with TemporaryDirectory() as temp:
            repository = Path(temp)
            project = repository / "project"
            config = project / ".harness/config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                'schema = 2\n[checks]\nquick = [["true"]]\nfull = [["true"]]\n'
                '[risk]\nsecurity_paths = ["src/**"]\nsecurity_keywords = []\n',
                encoding="utf-8",
            )
            application = project / "src/app.py"
            application.parent.mkdir()
            application.write_text("def app():\n    return 1\n", encoding="utf-8")
            unrelated = repository / "outside.txt"
            unrelated.write_text("baseline\n", encoding="utf-8")
            self.run_git(repository, "init", "-q")
            self.run_git(repository, "config", "user.name", "Harness Test")
            self.run_git(repository, "config", "user.email", "harness@example.test")
            self.run_git(repository, "add", ".")
            self.run_git(repository, "commit", "-qm", "baseline")

            application.write_text("def app():\n    return 2\n", encoding="utf-8")
            unrelated.write_text("changed outside the project\n", encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["risk", "--root", str(project)])

            report = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("T3", report["level"])
            self.assertTrue(report["security_review"])
            self.assertEqual(["src/app.py"], report["changed_paths"])

    def run_git(self, root: Path, *arguments: str) -> None:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
