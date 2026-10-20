import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.command_runner import run_bounded_command


class CommandActorTests(unittest.TestCase):
    def test_actor_mode_rejects_invalid_values_or_nonroot_nonlinux_before_spawn(self):
        with patch('scripts.command_runner.subprocess.Popen') as spawn:
            for value in (None, 1, 'true', []):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    run_bounded_command(['git','status'], cwd=Path('/'), timeout_seconds=1,
                                        max_output_bytes=1024, run_as_actor=value)
            for platform, uid in (('darwin',0), ('linux',1000)):
                with self.subTest(platform=platform,uid=uid), \
                        patch('scripts.command_runner.sys.platform', platform), \
                        patch('scripts.command_runner.os.geteuid', return_value=uid), self.assertRaises(ValueError):
                    run_bounded_command(['git','status'], cwd=Path('/'), timeout_seconds=1,
                                        max_output_bytes=1024, run_as_actor=True)
            spawn.assert_not_called()

    def test_callback_probe_and_final_git_both_use_actor_mode(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve(); script=root/'fixed-git.py'
            script.write_text("import sys\nif 'config' in sys.argv:raise SystemExit(1)\nprint('OK')\n")
            commands=[]
            def actor_command(argv, environment):
                commands.append(tuple(argv))
                return [sys.executable,str(script),*argv[1:]]
            with patch('scripts.command_runner.sys.platform','linux'), \
                    patch('scripts.command_runner.os.geteuid',return_value=0), \
                    patch('scripts.command_runner._actor_command',side_effect=actor_command):
                result=run_bounded_command(['git','diff'],cwd=root,timeout_seconds=3,
                                           max_output_bytes=1024,run_as_actor=True)
            self.assertEqual(0,result.returncode)
            self.assertEqual(2,len(commands))
            self.assertIn('config',commands[0]);self.assertIn('diff',commands[1])
            self.assertIn('--no-ext-diff',commands[1]);self.assertIn('--no-textconv',commands[1])

    def test_actor_mode_does_not_bypass_public_wrapped_git_guard(self):
        with patch('scripts.command_runner.sys.platform','linux'), \
                patch('scripts.command_runner.os.geteuid',return_value=0), \
                patch('scripts.command_runner._actor_command') as wrapper:
            result=run_bounded_command(['/usr/bin/setpriv','--reuid=2000','git','status'],
                cwd=Path('/'),timeout_seconds=1,max_output_bytes=1024,run_as_actor=True)
            self.assertFalse(result.started);self.assertEqual(125,result.returncode)
            wrapper.assert_not_called()

    def test_actor_prefix_is_fixed_and_uses_only_trusted_canonical_binaries(self):
        from scripts.command_runner import _actor_command
        selected=Path('/opt/git/bin/git')
        def metadata(path):
            kind=stat.S_IFREG if path in (selected,Path('/usr/bin/setpriv')) else stat.S_IFDIR
            return SimpleNamespace(st_uid=0,st_mode=kind|0o755)
        with patch('scripts.command_runner.shutil.which',return_value=str(selected)), \
                patch.object(Path,'resolve',lambda path,**kwargs:path), \
                patch.object(Path,'lstat',metadata):
            command=_actor_command(['git','rev-parse','HEAD'],{'PATH':'/opt/git/bin:/usr/bin'})
            for option in ('--reuid=2000','--regid=2000','--clear-groups','--no-new-privs',
                           '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all'):
                self.assertIn(option,command)
            self.assertEqual([str(selected),'rev-parse','HEAD'],command[command.index('--')+1:])
        for uid,mode in ((2000,stat.S_IFREG|0o755),(0,stat.S_IFREG|0o775),(0,stat.S_IFLNK|0o777)):
            with self.subTest(uid=uid,mode=mode), \
                    patch('scripts.command_runner.shutil.which',return_value=str(selected)), \
                    patch.object(Path,'resolve',lambda path,**kwargs:path), \
                    patch.object(Path,'lstat',return_value=SimpleNamespace(st_uid=uid,st_mode=mode)), \
                    self.assertRaises(ValueError):
                _actor_command(['git','status'],{'PATH':'/opt/git/bin'})
