from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import os
import unittest
from unittest.mock import patch

from evals.native_cgroup import (CgroupBinding, ProcessIdentity, Task, Namespace,
    bind_actor_cgroup, kill_actor_cgroup, parse_events, parse_pids, parse_task_stat)
from evals import native_cgroup as cgroup


class NativeCgroupTests(unittest.TestCase):
    unit = 'harness-eval-' + 'a' * 32 + '.service'
    namespace = Namespace('11111111-1111-4111-8111-111111111111', 11, 12)

    def test_kernel_parsers_reject_ambiguous_data(self):
        self.assertEqual((2, 4), parse_pids(b'4\n2\n4\n'))
        self.assertEqual((0, 0), parse_events(b'populated 0\nfrozen 0\n'))
        for data in (b'populated 0\npopulated 0\nfrozen 0\n', b'populated 0\n',
                     b'populated 2\nfrozen 0\n', b'populated true\nfrozen 0\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_events(data)
        for data in (b'0', b'-2', b'1.2', b'123\x00', b'2\n' * 1025, b'x' * (cgroup.LIMIT + 1), '2'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_pids(data)

    def test_stat_parser_ignores_arbitrary_comm_without_losing_generation(self):
        data = b'23 (name ) with\nspaces) S 10 ' + b'0 ' * 17 + b'99\n'
        self.assertEqual((ProcessIdentity(23, 99), 10, 'S'), parse_task_stat(23, data))
        for data in (b'24 (wrong) S 1', b'23 nope', b'23 (truncated) S 1'):
            with self.assertRaises(ValueError):
                parse_task_stat(23, data)

    def _binding(self, directory):
        metadata = directory.stat()
        return CgroupBinding(self.unit, 'b' * 32, self.namespace, metadata.st_dev, metadata.st_ino,
                             ProcessIdentity(23, 99), ProcessIdentity(10, 88))

    @contextmanager
    def _kernel(self, directory, *, tasks=(), remaining=None):
        binding = self._binding(directory)
        for name, data in (('cgroup.kill', ''), ('cgroup.events', 'populated 0\nfrozen 0\n'),
                           ('cgroup.procs', ''), ('cgroup.threads', '')):
            (directory / name).write_text(data)
        @contextmanager
        def opened(value):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd
            finally:
                os.close(fd)
        with patch('evals.native_cgroup._open_bound', side_effect=opened), \
                patch('evals.native_cgroup._matching_tasks', side_effect=[tasks, ()]), \
                patch('evals.native_cgroup._task', side_effect=lambda pid: (remaining or {}).get(pid)):
            yield binding

    def test_cleanup_pump_failure_keeps_kill_verification_and_preserves_interrupt(self):
        for failed in (False,True):
            with TemporaryDirectory() as temp:
                directory=Path(temp);observed=[]
                def pump():
                    observed.append((directory/'cgroup.kill').read_text())
                    if failed:raise KeyboardInterrupt('audit pump interrupted')
                with self._kernel(directory) as binding:
                    if failed:
                        with self.assertRaises(KeyboardInterrupt):kill_actor_cgroup(binding,pump=pump)
                    else:self.assertTrue(kill_actor_cgroup(binding,pump=pump).empty_verified)
                self.assertEqual(['1'],observed)

    def test_kill_verifies_empty_kernel_lists_and_reused_pids_are_unrelated(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            old = Task(ProcessIdentity(31, 120), 23, 'S', b'/old')
            reused = Task(ProcessIdentity(31, 121), 1, 'S', b'/unrelated')
            with self._kernel(directory, tasks=(old,), remaining={31: reused}) as binding:
                result = kill_actor_cgroup(binding, timeout_seconds=0.1)
            self.assertTrue(result.empty_verified)
            self.assertEqual((), result.remaining_generations)
            self.assertEqual((ProcessIdentity(23, 99), old.identity), result.observed_processes)
            self.assertEqual('1', (directory / 'cgroup.kill').read_text())

    def test_same_generation_outside_cgroup_cannot_be_reported_clean(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            escaped = Task(ProcessIdentity(31, 120), 23, 'S', b'/other')
            with self._kernel(directory, remaining={31: escaped}) as binding, \
                    patch('evals.native_cgroup._matching_tasks', return_value=()):
                result = kill_actor_cgroup(binding, tracked=(escaped.identity,), timeout_seconds=0.001)
            self.assertFalse(result.empty_verified)
            self.assertEqual((escaped.identity,), result.remaining_generations)

    def test_populated_or_zombie_members_are_not_empty(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            zombie = Task(ProcessIdentity(31, 120), 10, 'Z', b'/actor')
            with self._kernel(directory) as binding, \
                    patch('evals.native_cgroup._matching_tasks', return_value=(zombie,)):
                (directory / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
                (directory / 'cgroup.procs').write_text('31\n')
                result = kill_actor_cgroup(binding, timeout_seconds=0.001)
            self.assertFalse(result.empty_verified)
            self.assertEqual((zombie.identity,), result.members)
            self.assertEqual((31,), result.procs)

    def test_unsupported_host_and_unsafe_unit_fail_before_open(self):
        with patch('evals.native_cgroup.sys.platform', 'darwin'), \
                patch('evals.native_cgroup._root_directory') as opened, self.assertRaises(ValueError):
            bind_actor_cgroup(self.unit, 23)
        opened.assert_not_called()
        with patch('evals.native_cgroup._require_root_linux'), \
                patch('evals.native_cgroup._root_directory') as opened:
            for unit in ('system.slice', '../other.service', 'harness-eval-a.service'):
                with self.assertRaises(ValueError):
                    bind_actor_cgroup(unit, 23)
            opened.assert_not_called()

    def test_namespace_manager_and_inode_changes_prevent_kill(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            binding = self._binding(directory)
            (directory / 'cgroup.kill').write_text('')
            for changes in ({'namespace': replace(self.namespace, boot_id='changed')},
                            {'invocation_id': 'c' * 32}, {'inode': binding.inode + 1}):
                with self.subTest(changes=changes), patch('evals.native_cgroup._require_root_linux'), \
                        patch('evals.native_cgroup._namespace', return_value=self.namespace), \
                        patch('evals.native_cgroup._manager', return_value=('b' * 32, 10)), \
                        patch('evals.native_cgroup._root_directory', side_effect=lambda path: os.open(directory, os.O_RDONLY | os.O_DIRECTORY)), \
                        patch('evals.native_cgroup._task', return_value=Task(binding.guardian, 1, 'S', b'/system.slice/' + self.unit.encode())), \
                        self.assertRaises(ValueError):
                    kill_actor_cgroup(replace(binding, **changes), timeout_seconds=0.01)
                self.assertEqual('', (directory / 'cgroup.kill').read_text())

    def test_kernel_read_error_is_not_success(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            with self._kernel(directory) as binding:
                (directory / 'cgroup.events').unlink()
                with self.assertRaises(OSError):
                    kill_actor_cgroup(binding, timeout_seconds=0.01)

    def test_manager_projection_requires_exact_unit_and_execution_identity(self):
        good = ('MainPID=10\nControlGroup=/system.slice/' + self.unit + '\nInvocationID=' + 'b' * 32 + '\n').encode()
        for raw, valid in ((good, True), (good.replace(b'MainPID=10', b'MainPID=0'), False),
                           (good.replace(b'InvocationID=', b'Other='), False),
                           (good.replace(b'/system.slice/', b'/other.slice/'), False),
                           (good + b'MainPID=10\n', False)):
            with self.subTest(raw=raw), patch('evals.native_cgroup.subprocess.run',
                    return_value=SimpleNamespace(returncode=0, stdout=raw)) as run:
                if valid:
                    self.assertEqual(('b' * 32, 10), cgroup._manager(self.unit))
                else:
                    with self.assertRaises(ValueError):
                        cgroup._manager(self.unit)
                self.assertNotIn('shell', run.call_args.kwargs)
                self.assertEqual({'PATH': '/usr/bin:/bin'}, run.call_args.kwargs['env'])

    def test_admission_requires_dedicated_uid_groups_and_no_capabilities(self):
        good = (b'Uid:\t2000 2000 2000 2000\nGid:\t2000 2000 2000 2000\nGroups:\t2000\n'
                b'NoNewPrivs:\t1\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n')
        with patch('evals.native_cgroup._read_kernel', return_value=good):
            cgroup._secure_actor(23)
        with patch('evals.native_cgroup._read_kernel', return_value=good.replace(b'Groups:\t2000', b'Groups:')):
            cgroup._secure_actor(23)
        for raw in (good.replace(b'Uid:\t2000 2000 2000 2000', b'Uid:\t2000'),
                    good.replace(b'Groups:\t2000\n', b''),
                    good.replace(b'Groups:\t2000', b'Groups:\t0 2000'),
                    good.replace(b'NoNewPrivs:\t1', b'NoNewPrivs:\t0'),
                    good.replace(b'CapPrm:\t0', b'CapPrm:\t1')):
            with patch('evals.native_cgroup._read_kernel', return_value=raw), self.assertRaises(ValueError):
                cgroup._secure_actor(23)

    def test_proc_snapshot_includes_init_but_rejects_a_mid_read_generation_change(self):
        def raw(pid, start):
            return str(pid).encode() + b' (comm) S 10 ' + b'0 ' * 17 + str(start).encode()
        with patch('evals.native_cgroup._read_kernel', side_effect=[raw(1, 1), b'0::/init.scope\n', raw(1, 1)]):
            self.assertEqual(ProcessIdentity(1, 1), cgroup._task(1).identity)
        with patch('evals.native_cgroup._read_kernel', side_effect=[raw(23, 99), b'0::/actor\n', raw(23, 100)]), \
                self.assertRaises(ValueError):
            cgroup._task(23)
        with patch('evals.native_cgroup._read_kernel', side_effect=FileNotFoundError):
            self.assertIsNone(cgroup._task(23))
        with patch('evals.native_cgroup._read_kernel', side_effect=PermissionError), self.assertRaises(OSError):
            cgroup._task(23)

    def test_binding_preserves_kernel_generations_and_rejects_wrong_parent(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            guardian = Task(ProcessIdentity(10, 88), 1, 'S', ('/system.slice/' + self.unit).encode())
            actor = Task(ProcessIdentity(23, 99), 10, 'S', guardian.cgroup + b'/actor')
            with patch('evals.native_cgroup._require_root_linux'), \
                    patch('evals.native_cgroup._namespace', return_value=self.namespace), \
                    patch('evals.native_cgroup._manager', return_value=('b' * 32, 10)), \
                    patch('evals.native_cgroup._task', side_effect=lambda pid: actor if pid == 23 else guardian), \
                    patch('evals.native_cgroup._secure_actor'), \
                    patch('evals.native_cgroup._root_directory', side_effect=lambda path: os.open(directory, os.O_RDONLY | os.O_DIRECTORY)):
                result = bind_actor_cgroup(self.unit, 23)
                self.assertEqual(self._binding(directory), result)
                actor = replace(actor, parent_pid=11)
                with self.assertRaises(ValueError):
                    bind_actor_cgroup(self.unit, 23)

    def test_kernel_reads_are_bounded_and_control_directories_reject_writable_ancestors(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            file = directory / 'huge'
            file.write_bytes(b'x' * (cgroup.LIMIT + 1))
            with self.assertRaises(ValueError):
                cgroup._read_kernel(file)
            with self.assertRaises((ValueError, OSError)):
                cgroup._root_directory(directory)

    def test_post_kill_identity_change_prevents_a_successful_return(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in (('cgroup.kill', ''), ('cgroup.procs', ''), ('cgroup.threads', ''),
                                ('cgroup.events', 'populated 0\nfrozen 0\n')):
                (directory / name).write_text(value)
            binding = self._binding(directory)
            guardian = Task(binding.guardian, 1, 'S', ('/system.slice/' + self.unit).encode())
            with patch('evals.native_cgroup._require_root_linux'), \
                    patch('evals.native_cgroup._namespace', return_value=self.namespace), \
                    patch('evals.native_cgroup._manager', side_effect=[('b' * 32, 10), ('c' * 32, 10)]), \
                    patch('evals.native_cgroup._task', side_effect=lambda pid: guardian if pid in (10, os.getpid()) else None), \
                    patch('evals.native_cgroup._root_directory', side_effect=lambda path: os.open(directory, os.O_RDONLY | os.O_DIRECTORY)), \
                    patch('evals.native_cgroup._matching_tasks', return_value=()), \
                    patch('evals.native_cgroup.Path.lstat', return_value=directory.stat()), \
                    self.assertRaises(ValueError):
                kill_actor_cgroup(binding, timeout_seconds=0.01)
            self.assertEqual('1', (directory / 'cgroup.kill').read_text())

    def test_global_membership_does_not_confuse_sibling_paths_or_drop_zombies(self):
        prefix = ('/system.slice/' + self.unit + '/actor').encode()
        groups = {23: prefix, 24: prefix + b'/nested', 25: prefix + b'-other', 26: prefix + b' (deleted)'}
        tasks = {pid: Task(ProcessIdentity(pid, 99), 10, 'Z', group) for pid, group in groups.items()}
        entries = [SimpleNamespace(name=str(pid)) for pid in tasks] + [SimpleNamespace(name='self')]
        with TemporaryDirectory() as temp, patch('evals.native_cgroup.os.scandir') as scan, \
                patch('evals.native_cgroup._task', side_effect=lambda pid: tasks.get(pid)):
            scan.return_value.__enter__.return_value = iter(entries)
            result = cgroup._matching_tasks(self._binding(Path(temp)))
        self.assertEqual((23, 24, 26), tuple(task.identity.pid for task in result))
