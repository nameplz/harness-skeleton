"""Protected historical admission/cleanup proof; no live OS lookups on replay."""

from __future__ import annotations

from dataclasses import asdict
import re
from uuid import UUID

from evals.native_cgroup import MAX_TRACKED, UNIT
from evals.native_supervisor import SupervisorCleanup

BINDINGS = frozenset({'invocation_sha256', 'source_sha256', 'command_sha256',
    'session_sha256', 'policy_sha256', 'turn_sha256', 'environment_sha256', 'binary_sha256'})
BACKEND = 'linux-systemd-uid2000'


def _fields(value: object, expected: set | frozenset) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('invalid lifecycle fields')
    return value


def _number(value: object, minimum: int = 0, maximum: int = 2**64) -> int:
    if type(value) is not int or not minimum <= value < maximum:
        raise ValueError('invalid lifecycle numeric identity')
    return value


def _generation(value: object) -> tuple[int, int]:
    row = _fields(value, {'pid', 'start_ticks'})
    return _number(row['pid'], 2, 2**31), _number(row['start_ticks'])


def _binding(value: object) -> None:
    row = _fields(value, {'unit', 'invocation_id', 'namespace', 'device', 'inode', 'actor', 'guardian'})
    if not isinstance(row['unit'], str) or not UNIT.fullmatch(row['unit']) or \
            not isinstance(row['invocation_id'], str) or not re.fullmatch('[0-9a-f]{32}', row['invocation_id']):
        raise ValueError('invalid lifecycle systemd identity')
    namespace = _fields(row['namespace'], {'boot_id', 'pid', 'cgroup'})
    boot = namespace['boot_id']
    if not isinstance(boot, str) or str(UUID(boot)) != boot:
        raise ValueError('invalid historical boot identity')
    for value in (namespace['pid'], namespace['cgroup'], row['inode']):
        _number(value, 1)
    _number(row['device'])
    if _generation(row['actor']) == _generation(row['guardian']):
        raise ValueError('actor and guardian generations must differ')


def _bindings(value: object) -> dict:
    row = _fields(value, BINDINGS)
    if any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in row.values()):
        raise ValueError('invalid lifecycle digest binding')
    return row


def verify_lifecycle(record: object, bindings: dict, *, returncode: int) -> bool:
    row = _fields(record, {'schema', 'backend', 'bindings', 'binding', 'cleanup', 'receipt_verified'})
    if type(row['schema']) is not int or row['schema'] != 1 or row['backend'] != BACKEND or \
            row['receipt_verified'] is not True or _bindings(row['bindings']) != _bindings(bindings):
        raise ValueError('lifecycle policy or digest binding changed')
    _binding(row['binding'])
    cleanup = _fields(row['cleanup'], {'observation', 'actor_returncode', 'proxy_returncode',
                                      'guardian_reaped', 'unit_gone'})
    observation = _fields(cleanup['observation'], {'binding', 'observed_processes', 'members',
        'remaining_generations', 'populated', 'frozen', 'procs', 'threads'})
    _binding(observation['binding'])
    if observation['binding'] != row['binding']:
        raise ValueError('cleanup belongs to another admission')
    observed = observation['observed_processes']
    if not isinstance(observed, list) or not 1 <= len(observed) <= MAX_TRACKED:
        raise ValueError('lifecycle observed generations unavailable or unbounded')
    generations = tuple(_generation(value) for value in observed)
    if tuple(sorted(set(generations))) != generations or _generation(row['binding']['actor']) not in generations:
        raise ValueError('lifecycle observed generations omit the actor or are not sorted unique')
    if any(observation[name] != [] for name in ('members', 'remaining_generations', 'procs', 'threads')) or \
            any(type(observation[name]) is not int or observation[name] != 0 for name in ('populated', 'frozen')):
        raise ValueError('lifecycle has residual actor resources')
    if any(type(value) is not int or value != 0 for value in
           (returncode, cleanup['actor_returncode'], cleanup['proxy_returncode'])) or \
            cleanup['guardian_reaped'] is not True or cleanup['unit_gone'] is not True:
        raise ValueError('lifecycle actor, guardian or proxy did not finish normally')
    return True


def lifecycle_record(process, bindings: dict) -> dict:
    """Only the final cleanup_result is available after all launcher resources close."""
    result = process.cleanup_result
    if not isinstance(result, SupervisorCleanup) or result.observation.binding != process.binding:
        raise ValueError('final supervisor cleanup does not match actual admission')
    _bindings(bindings)
    if process.command_sha256 != bindings['command_sha256'] or \
            process.environment_sha256 != bindings['environment_sha256']:
        raise ValueError('lifecycle launch digests differ from actual supervisor')
    # JSON containers keep producer and historical reader under the same strict schema.
    import json
    record = json.loads(json.dumps({'schema': 1, 'backend': BACKEND, 'bindings': bindings,
        'binding': asdict(process.binding), 'cleanup': asdict(result), 'receipt_verified': True}))
    verify_lifecycle(record, bindings, returncode=process.returncode)
    return record
