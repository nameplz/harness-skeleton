from pathlib import Path
import tomllib
import unittest
import sys
import sysconfig

from evals.native_runtime import build_exec_command, build_review_command, sandbox_options, runtime_readable_roots


class NativeRuntimeTests(unittest.TestCase):
    def test_review_disables_candidate_project_config_and_optional_connected_tools(self) -> None:
        root = Path('/private/tmp/review-snapshot').resolve()
        command = build_review_command(root, model='exact-model')
        overrides = [command[index + 1] for index, value in enumerate(command) if value == '-c']
        # CLI overrides merge in order; the final project trust setting must win.
        config = tomllib.loads('\n'.join(overrides[:-1]))
        final = tomllib.loads(overrides[-1])
        self.assertEqual('untrusted', final['projects'][str(root)]['trust_level'])
        for feature in ('hooks', 'multi_agent', 'apps', 'plugins'):
            self.assertFalse(config['features'][feature])
        self.assertFalse(config['apps']['_default']['enabled'])

    def test_profile_denies_outside_access_and_preserves_native_workspace_protection(self) -> None:
        options = sandbox_options(writable=True, readable_roots=(Path('/usr/local'),))
        for i in range(0, len(options), 2):
            self.assertEqual('-c', options[i])
        config = tomllib.loads('\n'.join(options[1::2]))
        profile = config['permissions']['harness-eval']
        self.assertEqual(':workspace', profile['extends'])
        filesystem = profile['filesystem']
        self.assertEqual('deny', filesystem[':root'])
        self.assertEqual('deny', filesystem[':tmpdir'])
        self.assertEqual('deny', filesystem[':slash_tmp'])
        self.assertEqual('read', filesystem['/usr/local'])
        self.assertFalse(profile['network']['enabled'])
        self.assertEqual('none', config['shell_environment_policy']['inherit'])
        self.assertEqual('read', filesystem[':workspace_roots']['.eval-home'])

    def test_exec_does_not_override_profile_with_legacy_sandbox_or_user_rules(self) -> None:
        command = build_exec_command(Path('/private/tmp/fixture'), model='exact-model', writable=True)
        self.assertIn('--ignore-user-config', command)
        self.assertIn('--ignore-rules', command)
        self.assertNotIn('--ephemeral', command)  # 0.162.1 cannot spawn a child without its parent rollout.
        self.assertNotIn('--sandbox', command)
        self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', command)
        self.assertEqual('exact-model', command[command.index('--model') + 1])
        self.assertIn('features.hooks=false', command)
        self.assertIn('features.apps=false', command)
        self.assertIn('features.plugins=false', command)
        self.assertIn('projects={"/private/tmp/fixture"={trust_level="untrusted"}}', command)

    def test_runtime_allowlist_does_not_grant_entire_interpreter_prefix(self) -> None:
        roots = runtime_readable_roots()
        self.assertNotIn(Path(sys.executable).resolve().parents[1], roots)
        self.assertIn(Path(sys.executable).resolve().parent, roots)
        self.assertIn(Path(sysconfig.get_path('stdlib')).resolve(), roots)

    def test_grader_profile_grants_no_write_workspace(self) -> None:
        options = sandbox_options(writable=False)
        settings = ' '.join(options)
        self.assertIn(':read-only', settings)
        self.assertNotIn(':workspace"', settings)
        profile = tomllib.loads('\n'.join(options[1::2]))['permissions']['harness-eval']
        self.assertEqual('read', profile['filesystem'][':workspace_roots']['.'])

    def test_native_git_runtime_is_explicit_when_apple_toolchain_exists(self) -> None:
        toolchain = Path('/Library/Developer/CommandLineTools')
        command = build_exec_command(Path('/private/tmp/fixture'), model='exact-model', writable=True)
        if toolchain.is_dir():
            self.assertNotIn(toolchain, runtime_readable_roots())
            self.assertIn(toolchain / 'usr/bin', runtime_readable_roots())
            settings = '\n'.join(command)
            self.assertIn(str(toolchain / 'usr/bin'), settings)


if __name__ == '__main__':
    unittest.main()
