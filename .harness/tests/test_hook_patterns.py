import unittest

from scripts.hooks.agent_hook import _dangerous_reason, handle_event


class HookPatternTests(unittest.TestCase):
    def assert_blocked(self, commands):
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNotNone(_dangerous_reason(command))
                response = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}})
                output = response["hookSpecificOutput"]
                self.assertEqual("deny", output["permissionDecision"])
                self.assertTrue(output["permissionDecisionReason"].splitlines()[-1].startswith("Next: "))

    def test_wp10_ac1_rm_recursive_force_order_and_spelling(self):
        self.assert_blocked(["rm -rf dir", "rm -fr dir", "rm -Rf dir", "rm -fR dir", "rm -r -f dir",
                             "rm -f --recursive dir", "rm --recursive --force dir", "rm --force --recursive dir",
                             "echo ok; rm -fr dir", "echo ok\nrm -rf dir"])

    def test_wp10_ac1_git_push_force_forms(self):
        self.assert_blocked(["git push -f", "git push --force", "git push --force-with-lease",
                             "git push --force-with-lease=main:abc", "git push origin +main:main",
                             "git -C repo push -f", "git push -- origin +main:main"])

    def test_wp10_ac2_mv2_commit_and_config_gate_bypasses(self):
        self.assert_blocked(["git commit -n -m x", "git commit --no-verify -m x", "git commit -nm x",
                             "git -c core.hooksPath=/dev/null commit -m x", "git -ccore.hooksPath=/dev/null commit -m x",
                             "git -C repo -c core.hooksPath=/dev/null commit -m x",
                             "git config core.hooksPath /dev/null", "git config --local core.hooksPath /dev/null",
                             "git config --unset core.hooksPath", "git config --unset-all core.hooksPath",
                             "git config set core.hooksPath /dev/null", "git config unset core.hooksPath"])

    def test_wp10_git_clean_force(self):
        self.assert_blocked(["git clean -f", "git clean -fd", "git clean -dfx", "git clean --force"])

    def test_wp10_ac3_allows_normal_commands_and_quoted_values(self):
        commands = ["rm -r dir", "rm -f file", "rm --recursive dir", "rm -- -rf", "git push",
                    'git commit -m "fix -n handling"', 'git commit -m "-n"', 'git commit -m"fix -n handling"',
                    'git commit --message="--no-verify"', "git commit -- --no-verify",
                    "git -c user.name=Test commit -m x", "git config core.hooksPath",
                    "git config --get core.hooksPath", "git config get core.hooksPath", "git clean -n",
                    'echo "rm -rf dir"', 'echo ";" rm -rf dir', 'git commit -m "fix; rm -rf spelling"',
                    'git push -o "--force"', 'git clean -e "-f"']
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNone(_dangerous_reason(command))
                self.assertIsNone(handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}))

    def test_wp10_wrapper_limit_and_existing_reset_sql_rules(self):
        for command in ["bash -c 'rm -rf dir'", 'sh -c "git push -f"']:
            self.assertIsNone(_dangerous_reason(command))
        self.assert_blocked(["git reset --hard HEAD", "psql -c 'DROP TABLE users'"])

    def test_wp10_ac4_mv6_malformed_command_does_not_crash_feedback(self):
        self.assertIsNone(_dangerous_reason('git commit -m "unterminated'))

    def test_wp10_review1_command_prefixes(self):
        self.assert_blocked(["sudo rm -rf /tmp/x", "FOO=1 rm -rf x", "env rm -rf x", "command rm -rf x",
                             "time rm -rf x", "xargs rm -rf", "nohup git push --force",
                             "sudo -u root rm -rf x", "doas -u root rm -rf x", "env -u FOO rm -rf x",
                             "command -p rm -rf x", "exec -a cleanup rm -rf x", "nohup -- rm -rf x",
                             "time -f %e rm -rf x", "nice -n 5 rm -rf x", "xargs -n 1 rm -rf",
                             "sudo -uroot rm -rf x", "sudo --user=root rm -rf x", "nice -n5 rm -rf x",
                             "FOO=1 env BAR=2 sudo -u root command rm -rf x"])

    def test_wp10_review2_malformed_tail_preserves_dangerous_commands(self):
        self.assert_blocked(["rm -rf x; echo 'oops", 'rm -rf x && echo "a',
                             "echo safe; rm -rf 'oops", 'git commit -n -m "oops'])

    def test_wp10_review1_ac3_prefixes_preserve_safe_commands_and_wrappers(self):
        for command in ["sudo -u root rm -r dir", "env git push", 'command git commit -m "fix -n handling"',
                        'FOO=1 nice -n 5 git commit -m "-n"', "sudo bash -c 'rm -rf x'",
                        "env FOO=1 sh -c 'git push -f'", "sudo -u root echo rm -rf x"]:
            with self.subTest(command=command):
                self.assertIsNone(_dangerous_reason(command))
