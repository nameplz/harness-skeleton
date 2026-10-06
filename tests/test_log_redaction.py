from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.harness_common import sanitize_log  # noqa: E402


class LogRedactionTests(unittest.TestCase):
    def test_unquoted_multiline_secret_value_is_redacted_to_record_boundary(self) -> None:
        result = sanitize_log("token=super secret\ncontinuation-secret\n\nnext record")
        empty_value = sanitize_log("token=\n\nnext record")

        self.assertNotIn("super secret", result)
        self.assertNotIn("continuation-secret", result)
        self.assertIn("next record", result)
        self.assertIn("next record", empty_value)
