from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.phase_worktree import (  # noqa: E402
    PhaseWorktreeError,
    ensure_phase_completed,
    validate_phase_name,
    write_heartbeat,
)


class PhaseWorktreeTests(unittest.TestCase):
    def test_phase_name_rejects_path_traversal(self) -> None:
        with self.assertRaises(PhaseWorktreeError):
            validate_phase_name("../bad")

    def test_incomplete_phase_blocks_open_pr(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            phase_dir = root / "phases/0-mvp"
            phase_dir.mkdir(parents=True)
            (phase_dir / "index.json").write_text(
                json.dumps(
                    {
                        "project": "demo",
                        "phase": "0-mvp",
                        "steps": [{"step": 0, "name": "setup", "status": "pending"}],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(PhaseWorktreeError):
                ensure_phase_completed(root, "0-mvp")

    def test_heartbeat_writes_ignored_runtime_state_shape(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)

            path = write_heartbeat(
                root=root,
                phase="0-mvp",
                step=2,
                attempt=3,
                status="running",
                message="working",
            )

            self.assertEqual(root / ".harness/runtime/0-mvp/step2-attempt3.json", path)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("0-mvp", data["phase"])
            self.assertEqual(2, data["step"])
            self.assertEqual(3, data["attempt"])
            self.assertEqual("running", data["status"])


if __name__ == "__main__":
    unittest.main()
