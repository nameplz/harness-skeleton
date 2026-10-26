from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.harness_risk import classify_risk, inspect_git_risk


def diff(path, changes, *, old=None, new=None):
    return (f"diff --git a/{path} b/{path}\n"
            f"--- {old or 'a/' + path}\n+++ {new or 'b/' + path}\n"
            f"@@ -1 +1 @@\n{changes}\n")


class TestWeakeningRiskTests(unittest.TestCase):
    def assert_weakening(self, paths, content, level="T2", **rules):
        result = classify_risk(paths, content, **rules)
        self.assertIn("test_weakening", result.reasons)
        self.assertEqual(level, result.level)
        self.assertTrue(result.code_review)
        return result

    def test_deleted_test_including_empty_file(self):
        for body in ("-assert ready", ""):
            with self.subTest(body=body):
                self.assert_weakening(["tests/test_app.py"], diff("tests/test_app.py", body, new="/dev/null"))
        for path in ("tests/test_empty.py", "tests/test empty.py"):
            content = f"diff --git a/{path} b/{path}\ndeleted file mode 100644\nindex e69de29..0000000\n"
            self.assert_weakening([path], content)

    def test_assertion_line_net_decrease(self):
        for assertion in ("assert ready", "self.assertEqual(1, actual)", "assert_eq!(1, actual)", "assert(ok)"):
            with self.subTest(assertion=assertion):
                self.assert_weakening(["tests/test_app.py"], diff("tests/test_app.py", "-" + assertion))

    def test_added_disable_markers(self):
        for marker in ("@unittest.skip('later')", "@unittest.skipIf(True, 'later')", "@pytest.mark.skip",
                       "@pytest.mark.skipif(True)", "@pytest.mark.xfail", "test.skip('later')",
                       "describe.only('one')", "t.Skip(\"later\")", "#[ignore]"):
            with self.subTest(marker=marker):
                self.assert_weakening(["tests/test_app.py"], diff("tests/test_app.py", "+" + marker))

    def test_go_test_path(self):
        self.assert_weakening(["app_test.go"], diff("app_test.go", '+t.Skip("later")'))

    def test_single_file_diff_snippets_keep_classifier_convention(self):
        for body in ("-assert ready", "+@pytest.mark.skip"):
            self.assert_weakening(["test_app.py"], body)

    def test_stronger_or_rewritten_tests_have_no_signal(self):
        for body, old in (("+assert ready", None), ("-assert old\n+assert new", None),
                          ("+def test_new():\n+    assert ready", "/dev/null"),
                          ("+@pytest.mark.skip", "/dev/null"), ("-@pytest.mark.skip", None)):
            with self.subTest(body=body, old=old):
                result = classify_risk(["tests/test_app.py"], diff("tests/test_app.py", body, old=old))
                self.assertNotIn("test_weakening", result.reasons)
                self.assertEqual("T1", result.level)

    def test_non_test_disable_strings_do_not_trigger(self):
        content = diff("src/app.py", '+skip = True\n+value = ".only"\n-assert ready')
        result = classify_risk(["src/app.py", "tests/test_app.py"], content)
        self.assertNotIn("test_weakening", result.reasons)

    def test_assertions_are_counted_per_file(self):
        content = diff("tests/test_a.py", "-assert ready") + diff("tests/test_b.py", "+assert ready")
        self.assert_weakening(["tests/test_a.py", "tests/test_b.py"], content)

    def test_assertions_are_counted_across_hunks(self):
        content = diff("tests/test_app.py", "-assert old\n@@ -8 +8 @@\n+assert new")
        self.assertNotIn("test_weakening", classify_risk(["tests/test_app.py"], content).reasons)

    def test_hard_tiers_cannot_be_lowered_by_custom_rules(self):
        content = diff("tests/test_app.py", "-assert ready")
        self.assert_weakening(["tests/test_app.py"], content, security_paths=[], security_keywords=[])
        for paths, extra in ((["tests/test_app.py", ".codex/config.toml"], ""),
                             (["tests/test_app.py"], "+subprocess.run(argv)")):
            with self.subTest(paths=paths):
                result = self.assert_weakening(paths, content + extra, level="T3")
                self.assertTrue(result.security_review)

    def test_untracked_tests_do_not_contaminate_tracked_test_diff(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "test_new.py").write_text("@pytest.mark.skip\nassert ready\n", encoding="utf-8")
            for body in ("+assert ready", "-assert ready"):
                def git_output(_root, argv, **_kwargs):
                    if argv[0] == "rev-parse":
                        return str(root)
                    if argv[0] == "ls-files":
                        return "test_new.py\0"
                    if "--name-only" in argv:
                        return "tests/test_app.py\0"
                    self.assertIn("--no-renames", argv)
                    return diff("tests/test_app.py", body)

                with self.subTest(body=body), patch("scripts.harness_risk._git_output", side_effect=git_output), \
                        patch("scripts.harness_risk._git_has_head", return_value=True):
                    result = inspect_git_risk(root, load_config_fn=lambda _: None)
                    self.assertEqual(body.startswith("-"), "test_weakening" in result.reasons)


if __name__ == "__main__":
    unittest.main()
