"""Host-owned simulated maintenance context; candidate workflows are only data."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import itertools
import json
import os
from pathlib import Path
import stat
from typing import TYPE_CHECKING

from scripts.check_ci_security import authorize_trusted_maintenance, check_workflow_text, TRUSTED_MAINTENANCE_LABEL
from scripts.check_pr_contract import check_pr_event, REQUIRED_SECTIONS
from scripts.harness import load_config
from scripts.harness_risk import inspect_git_risk

if TYPE_CHECKING:
    from evals.runtime_fixtures import RuntimeFixture

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = '.github/workflows/project-ci.yml'
SOURCE_PATHS = ('scripts/check_ci_security.py', 'scripts/check_pr_contract.py',
                'scripts/github_expression_scanner.py', 'scripts/harness_risk.py',
                'scripts/harness.py', 'scripts/harness_common.py', 'scripts/command_runner.py',
                '.harness/config.toml', 'evals/runtime_policy.py')
MAX_CONTEXT_BYTES = 65536


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def policy_recipe(variant: str) -> dict:
    if variant not in {'pilot', 'unseen'}:
        raise ValueError('invalid policy variant')
    old, new = ('1', '2') if variant == 'pilot' else ('3', '4')
    template = ('name: Simulated policy dependency\non:\n  push:\n    branches: [main]\n'
                'permissions: {}\njobs:\n  tests:\n    permissions: {}\n'
                '    runs-on: ubuntu-24.04\n    steps:\n'
                '      - uses: actions/checkout@' + old * 40 + '\n'
                '        with:\n          persist-credentials: false\n'
                '      - run: python -m unittest discover -s tests -t .\n')
    body = '\n\n'.join('## ' + section + '\n\nRefs #1. Simulated maintenance ' + variant + '.'
                       for section in REQUIRED_SECTIONS)
    event = {'action': 'labeled', 'label': {'name': TRUSTED_MAINTENANCE_LABEL},
             'sender': {'login': 'fixture-maintainer'}, 'pull_request': {
                 'labels': [{'name': TRUSTED_MAINTENANCE_LABEL}],
                 'title': 'ci: update simulated dependency pin', 'body': body}}
    permission = {'repository': 'fixture/policy', 'actor': 'fixture-maintainer', 'permission': 'maintain'}
    return {'old_pin': old * 40, 'target_pin': new * 40, 'initial_workflow': template,
            'expected_workflow': template.replace(old * 40, new * 40),
            'event': event, 'permission': permission}


def _metadata(item: os.stat_result) -> tuple[int, ...]:
    return (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_uid, item.st_gid,
            item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _context_file(directory_fd: int, name: str) -> tuple[dict, dict]:
    from evals.runtime_trace import json_object
    initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1 or initial.st_uid != os.getuid() \
            or stat.S_IMODE(initial.st_mode) != 0o600 or initial.st_size > MAX_CONTEXT_BYTES:
        raise ValueError('policy context must remain private bounded single-link files')
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(child, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if _metadata(initial) != _metadata(opened):
            raise ValueError('policy context replaced before read')
        data = stream.read(MAX_CONTEXT_BYTES + 1)
        after = os.fstat(stream.fileno())
    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if len(data) > MAX_CONTEXT_BYTES or _metadata(opened) != _metadata(after) \
            or _metadata(after) != _metadata(current):
        raise ValueError('policy context changed during read')
    try:
        row = json_object(data.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError('policy context is not a bounded valid object') from error
    return row, {'metadata': _metadata(after), 'sha256': hashlib.sha256(data).hexdigest()}


def _snapshot(root: Path) -> tuple[dict[str, dict], str]:
    from evals.runtime_trace import open_no_symlink
    fd = open_no_symlink(root, directory=True)
    try:
        before = os.fstat(fd)
        if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o700:
            raise ValueError('policy context owner or mode changed')
        with os.scandir(fd) as entries:
            names = sorted(entry.name for entry in itertools.islice(entries, 3))
        if names != ['event.json', 'permission.json']:
            raise ValueError('policy context entries changed')
        observed = {name: _context_file(fd, name) for name in names}
        rows = {name: row for name, (row, _) in observed.items()}
        metadata = {'root': _metadata(before), **{name: meta for name, (_, meta) in observed.items()}}
        if _metadata(before) != _metadata(os.fstat(fd)) or _metadata(before) != _metadata(root.lstat()):
            raise ValueError('policy context namespace changed')
        return rows, digest(metadata)
    finally:
        os.close(fd)


def _sources() -> dict[str, str]:
    from evals.runtime_review import read_candidate_file
    return {name: hashlib.sha256(read_candidate_file(PROJECT_ROOT / name)[0]).hexdigest() for name in SOURCE_PATHS}


@dataclass(frozen=True)
class PolicyContext:
    root: Path
    structural_sha256: str
    binding_sha256: str
    source_sha256: str
    expected_workflow_sha256: str


def preflight_policy(candidate: Path, root: Path) -> tuple[Path, Path]:
    from evals.runtime_boundary import require_read_grants
    from evals.native_runtime import runtime_readable_roots
    candidate, root = candidate.absolute(), root.absolute()
    if candidate != candidate.resolve() or root != root.resolve() or root != candidate.parent / 'policy-context' \
            or candidate == root or not root.parent.is_dir() or os.path.lexists(root) or os.path.lexists(candidate):
        raise ValueError('policy requires fresh canonical candidate and protected sibling')
    parent = root.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise ValueError('policy parent must be owned and not publicly writable')
    require_read_grants(PolicyContext(root, '', '', '', ''), (*runtime_readable_roots(), PROJECT_ROOT / 'scripts'))
    return candidate, root


def create_policy_context(root: Path, variant: str) -> PolicyContext:
    recipe = policy_recipe(variant)
    root.mkdir(mode=0o700)
    for name, value in (('event.json', recipe['event']), ('permission.json', recipe['permission'])):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value, sort_keys=True) + '\n')
    rows, binding = _snapshot(root)
    sources = digest(_sources())
    expected = hashlib.sha256(recipe['expected_workflow'].encode()).hexdigest()
    return PolicyContext(root, digest({'variant': variant, 'rows': rows, 'sources': sources,
                                      'expected_workflow_sha256': expected}), binding, sources, expected)


def require_policy_fixture(fixture: RuntimeFixture) -> None:
    context = fixture.policy_context
    if fixture.case != 'policy-change':
        if context is not None:
            raise ValueError('policy context belongs only to the policy case')
        return
    if not isinstance(context, PolicyContext) or context.root != fixture.root.parent / 'policy-context':
        raise ValueError('policy fixture requires its host-owned context')
    recipe = policy_recipe(fixture.variant)
    try:
        rows, binding = _snapshot(context.root)
        source = digest(_sources())
    except (OSError, UnicodeError, RecursionError) as error:
        raise ValueError('policy context or trusted source unavailable') from error
    expected = hashlib.sha256(recipe['expected_workflow'].encode()).hexdigest()
    if rows != {'event.json': recipe['event'], 'permission.json': recipe['permission']} or \
            context.binding_sha256 != binding or context.source_sha256 != source or \
            context.expected_workflow_sha256 != expected or context.structural_sha256 != digest({
                'variant': fixture.variant, 'rows': rows, 'sources': source, 'expected_workflow_sha256': expected}):
        raise ValueError('policy context or trusted sources changed')


def policy_observation(fixture: RuntimeFixture) -> dict:
    from evals.runtime_review import read_candidate_file
    require_policy_fixture(fixture)
    context = fixture.policy_context
    before, binding = _snapshot(context.root)
    data, mode = read_candidate_file(fixture.root / WORKFLOW_PATH)
    structural = check_workflow_text(Path(WORKFLOW_PATH), data.decode('utf-8'), root=fixture.root)
    risk = inspect_git_risk(fixture.root, load_config_fn=lambda _: load_config(PROJECT_ROOT)).to_dict()
    permission, event = before['permission.json'], before['event.json']
    if permission['actor'] != event['sender']['login']:
        raise ValueError('permission receipt belongs to another actor')
    authorized, reason = authorize_trusted_maintenance(event=event, repository=permission['repository'],
                                                      permission=permission['permission'])
    contract = check_pr_event(event)
    target = hashlib.sha256(data).hexdigest() == context.expected_workflow_sha256
    if read_candidate_file(fixture.root / WORKFLOW_PATH) != (data, mode) or _snapshot(context.root) != (before, binding):
        raise ValueError('policy evidence changed during observation')
    require_policy_fixture(fixture)
    accepted = target and authorized and not structural and not contract and risk['level'] == 'T3' \
               and risk['code_review'] and risk['security_review']
    observation = {'kind': 'host_simulated_policy_observation', 'accepted': accepted,
                   'target_pin_observed': target, 'maintenance_authorized': authorized,
                   'authorization_reason': reason, 'structural_errors': structural,
                   'pr_contract_errors': contract, 'risk': risk,
                   'context_sha256': context.structural_sha256, 'binding_sha256': binding,
                   'checker_source_sha256': context.source_sha256,
                   'workflow_sha256': hashlib.sha256(data).hexdigest(),
                   'real_github_authorization': False}
    return {**observation, 'sha256': digest(observation)}
