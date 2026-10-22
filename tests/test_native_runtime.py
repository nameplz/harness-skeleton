from pathlib import Path
import tomllib
import unittest
import sys
import sysconfig
import json
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from evals.native_runtime import build_exec_command, build_review_command, sandbox_options, runtime_readable_roots
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source
from evals.runtime_review import freeze_for_review


class NativeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.fixture = materialize_fixture('documentation', self.root / 'candidate', condition='baseline')

    def tearDown(self) -> None:
        snapshot = self.root / 'snapshot'
        if snapshot.exists():
            snapshot.chmod(0o755)
            for path in snapshot.rglob('*'):
                if path.is_dir(): path.chmod(0o755)
        self.temp.cleanup()

    def _invocation(self, *, review=False):
        manifest = freeze_for_review(self.fixture, self.root / 'snapshot') if review else None
        source = write_frozen_source(self.fixture, self.root / 'source.json')
        return issue_invocation(self.fixture, self.root / 'launch', source, model='exact-model',
                                kind='correctness' if review else 'worker',
                                execution_root=self.root / 'snapshot' if review else self.fixture.root,
                                final_manifest_sha256=manifest['sha256'] if manifest else None)

    def test_missing_or_stale_source_preflight_cannot_build_a_model_command(self) -> None:
        with self.assertRaises(ValueError):
            build_exec_command(self.fixture.root, model='exact-model', writable=True)
        invocation = self._invocation()
        with patch('evals.runtime_invocation.source_file_hashes', return_value={}):
            with self.assertRaises(ValueError):
                build_exec_command(self.fixture.root, model='exact-model', writable=True, invocation=invocation)

    def test_review_disables_candidate_project_config_and_optional_connected_tools(self) -> None:
        invocation = self._invocation(review=True)
        root = invocation.execution_root
        command = build_review_command(root, model='exact-model', invocation=invocation)
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
        invocation = self._invocation()
        command = build_exec_command(self.fixture.root, model='exact-model', writable=True, invocation=invocation)
        self.assertIn('--ignore-user-config', command)
        self.assertIn('--ignore-rules', command)
        self.assertNotIn('--ephemeral', command)  # 0.162.1 cannot spawn a child without its parent rollout.
        self.assertNotIn('--sandbox', command)
        self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', command)
        self.assertEqual('exact-model', command[command.index('--model') + 1])
        self.assertIn('features.hooks=false', command)
        self.assertIn('features.apps=false', command)
        self.assertIn('features.plugins=false', command)
        self.assertIn('projects={' + json.dumps(str(self.fixture.root)) + '={trust_level="untrusted"}}', command)
        settings = '\n'.join(command)
        self.assertIn(invocation.nonce, settings)
        self.assertIn(invocation.sha256, settings)

    def test_runtime_allowlist_does_not_grant_entire_interpreter_prefix(self) -> None:
        roots = runtime_readable_roots()
        self.assertNotIn(Path(sys.executable).resolve().parents[1], roots)
        self.assertIn(Path(sys.executable).resolve().parent, roots)
        self.assertIn(Path(sysconfig.get_path('stdlib')).resolve(), roots)

    def test_macos_runtime_allowlist_grants_only_python_libffi_files(self) -> None:
        libdir = self.root / 'python-lib'
        libdir.mkdir()
        libffi = libdir / 'libffi.8.dylib'
        libffi.touch()
        (libdir / 'libffi.dylib').symlink_to(libffi.name)
        outside = self.root / 'outside'
        outside.mkdir()
        external_libffi = outside / 'libffi.external.dylib'
        external_libffi.touch()
        (libdir / external_libffi.name).symlink_to(external_libffi)
        get_config_var = sysconfig.get_config_var

        def config_var(name):
            return str(libdir) if name == 'LIBDIR' else get_config_var(name)

        with patch('evals.native_runtime.sys', SimpleNamespace(executable=sys.executable,
                                                               platform='darwin')):
            with patch('evals.native_runtime.sysconfig.get_config_var', side_effect=config_var):
                roots = runtime_readable_roots()

        self.assertIn(libffi.resolve(), roots)
        self.assertEqual(1, roots.count(libffi.resolve()))
        self.assertNotIn(external_libffi.resolve(), roots)
        self.assertNotIn(libdir.resolve(), roots)
        options = sandbox_options(writable=True, readable_roots=roots)
        filesystem = tomllib.loads('\n'.join(options[1::2]))['permissions']['harness-eval']['filesystem']
        self.assertEqual('read', filesystem[str(libffi.resolve())])
        self.assertNotIn(str(libdir.resolve()), filesystem)

    def test_linux_reexecution_grants_only_the_explicit_native_file(self) -> None:
        binary = Path('/opt/owned-codex/bin/codex')
        with patch('evals.native_runtime.sys', SimpleNamespace(executable=sys.executable, platform='linux')):
            roots = runtime_readable_roots(native_binary=binary)
            self.assertIn(binary, roots)
            self.assertNotIn(binary.parent, roots)
            self.assertNotIn(binary.parent.parent, roots)
            self.assertNotIn(binary, runtime_readable_roots())
            with self.assertRaises(ValueError):
                runtime_readable_roots(native_binary=Path('relative/codex'))
        with patch('evals.native_runtime.sys', SimpleNamespace(executable=sys.executable, platform='darwin')):
            self.assertEqual(runtime_readable_roots(), runtime_readable_roots(native_binary=binary))

    def test_grader_profile_grants_no_write_workspace(self) -> None:
        options = sandbox_options(writable=False)
        settings = ' '.join(options)
        self.assertIn(':read-only', settings)
        self.assertNotIn(':workspace"', settings)
        profile = tomllib.loads('\n'.join(options[1::2]))['permissions']['harness-eval']
        self.assertEqual('read', profile['filesystem'][':workspace_roots']['.'])

    def test_native_git_runtime_is_explicit_when_apple_toolchain_exists(self) -> None:
        toolchain = Path('/Library/Developer/CommandLineTools')
        command = build_exec_command(self.fixture.root, model='exact-model', writable=True, invocation=self._invocation())
        if toolchain.is_dir():
            self.assertNotIn(toolchain, runtime_readable_roots())
            self.assertIn(toolchain / 'usr/bin', runtime_readable_roots())
            settings = '\n'.join(command)
            self.assertIn(str(toolchain / 'usr/bin'), settings)


if __name__ == '__main__':
    unittest.main()
