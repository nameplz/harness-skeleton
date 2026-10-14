"""Host-issued, one-use launch identities backed by an external source freeze."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
from uuid import UUID

from evals.runtime_cases import case_spec
from evals.runtime_limits import metadata_seed_rows, require_failure_fixture
from evals.runtime_boundary import observe_boundary, require_boundary, require_disjoint, requested_policy_sha256
from evals.runtime_fixtures import PROJECT_ROOT, RuntimeFixture
from evals.runtime_trace import json_object, open_no_symlink, read_protected_artifact


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_file_hashes() -> dict[str, str]:
    patterns = ('evals/*.py', 'evals/*.json', 'scripts/*.py', 'tests/*.py', 'docs/**/*.md',
                '.codex/**/*.toml', '.codex/hooks/*.py', '.agents/skills/**/*.md', '.harness/*', 'AGENTS.md')
    paths = sorted({path for pattern in patterns for path in PROJECT_ROOT.glob(pattern)})
    result = {}
    for path in paths:
        with os.fdopen(open_no_symlink(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                raise ValueError('frozen source must be bounded and regular')
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError('frozen source exceeded its byte limit')
        result[path.relative_to(PROJECT_ROOT).as_posix()] = hashlib.sha256(content).hexdigest()
    return result


@dataclass(frozen=True)
class FrozenSource:
    path: Path
    manifest_sha256: str
    source_sha256: str


def load_frozen_source(fixture: RuntimeFixture, path: Path, digest: str) -> FrozenSource:
    record = json_object(read_protected_artifact(path, fixture, digest))
    current = source_file_hashes()
    if set(record) != {'schema', 'files_sha256'} or type(record['schema']) is not int or record['schema'] != 1 \
            or record['files_sha256'] != current:
        raise ValueError('frozen source file set or content changed')
    return FrozenSource(path.resolve(), digest, _digest(current))


def write_frozen_source(fixture: RuntimeFixture, path: Path) -> FrozenSource:
    require_boundary(fixture)
    require_failure_fixture(fixture)
    path = path.absolute()
    require_disjoint(fixture.protected_resource, path)
    if path.is_relative_to(fixture.root) or path.resolve().is_relative_to(fixture.root):
        raise ValueError('source freeze must be outside candidate control')
    record = {'schema': 1, 'files_sha256': source_file_hashes()}
    raw = (json.dumps(record, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
    return load_frozen_source(fixture, path, hashlib.sha256(raw).hexdigest())


@dataclass(frozen=True)
class Invocation:
    nonce: str
    kind: str
    fixture: RuntimeFixture
    execution_root: Path
    artifact_root: Path
    source: FrozenSource
    model: str
    final_manifest_sha256: str | None = None
    session_id: str | None = None
    command_sha256: str | None = None
    native_receipt_sha256: str | None = None

    @property
    def identity(self) -> dict[str, object]:
        identity = {'nonce': self.nonce, 'kind': self.kind, 'candidate_root': str(self.fixture.root),
                'execution_root': str(self.execution_root), 'artifact_root': str(self.artifact_root),
                'case': self.fixture.case, 'condition': self.fixture.condition, 'seed_head': self.fixture.seed_head,
                'seed_manifest_sha256': _digest({'files': self.fixture.seed_files, 'modes': self.fixture.seed_modes}),
                'git_control_manifest_sha256': _digest(self.fixture.git_control_files),
                'spec_sha256': case_spec(self.fixture.case).sha256, 'model': self.model,
                'fixture_sha256': self.fixture.fixture_sha256, 'variant': self.fixture.variant,
                'task_prompt_sha256': hashlib.sha256(self.fixture.prompt.encode()).hexdigest(),
                'source_manifest_sha256': self.source.manifest_sha256, 'source_sha256': self.source.source_sha256,
                'final_manifest_sha256': self.final_manifest_sha256}
        if self.fixture.protected_resource is not None:
            resource = self.fixture.protected_resource
            identity['protected_resource_sha256'] = resource.structural_sha256
            identity['protected_resource_binding_sha256'] = resource.binding_sha256
            identity['requested_boundary_policy_sha256'] = resource.requested_policy_sha256
        if self.fixture.validation_plan is not None:
            identity['validation_plan_sha256'] = self.fixture.validation_plan.sha256
            identity['metadata_only_seed_sha256'] = _digest(metadata_seed_rows(self.fixture))
        return identity

    @property
    def sha256(self) -> str:
        return _digest(self.identity)


def issue_invocation(fixture: RuntimeFixture, artifact_root: Path, source: FrozenSource, *, model: str,
                     kind: str = 'worker', execution_root: Path | None = None,
                     final_manifest_sha256: str | None = None) -> Invocation:
    require_boundary(fixture)
    require_failure_fixture(fixture)
    if source != load_frozen_source(fixture, source.path, source.manifest_sha256):
        raise ValueError('source identity changed before launch')
    if kind not in {'worker', 'correctness', 'security'} or not isinstance(model, str) or not model.strip():
        raise ValueError('invalid invocation kind or model')
    root = artifact_root.absolute()
    require_disjoint(fixture.protected_resource, root)
    if fixture.protected_resource is not None and observe_boundary(fixture.protected_resource).state != 'intact':
        raise ValueError('protected resource identity changed before launch')
    if root.exists() or root.is_symlink() or root.is_relative_to(fixture.root) or root.resolve().is_relative_to(fixture.root):
        raise ValueError('invocation needs a fresh protected artifact directory')
    cwd = (execution_root or fixture.root).resolve(strict=True)
    require_disjoint(fixture.protected_resource, cwd)
    if kind == 'worker' and (cwd != fixture.root or final_manifest_sha256 is not None):
        raise ValueError('worker invocation must use its candidate')
    if kind != 'worker' and (cwd.is_relative_to(fixture.root) or not isinstance(final_manifest_sha256, str)
                            or len(final_manifest_sha256) != 64):
        raise ValueError('review invocation needs a fixed external snapshot')
    root.mkdir(mode=0o700)
    invocation = Invocation(secrets.token_hex(32), kind, fixture, cwd, root.resolve(), source, model, final_manifest_sha256)
    (invocation.artifact_root / 'invocation.json').write_text(json.dumps(invocation.identity, indent=2) + '\n')
    return invocation


def verify_invocation(fixture: RuntimeFixture, invocation: Invocation, *, require_session: bool = False) -> None:
    require_boundary(fixture)
    require_failure_fixture(fixture)
    if not isinstance(invocation, Invocation) or invocation.fixture != fixture:
        raise ValueError('invocation is not for this fixture')
    if invocation.source != load_frozen_source(fixture, invocation.source.path, invocation.source.manifest_sha256):
        raise ValueError('invocation source changed')
    if fixture.protected_resource is not None and fixture.protected_resource.requested_policy_sha256 != requested_policy_sha256():
        raise ValueError('requested boundary policy changed')
    record_path = invocation.artifact_root / 'invocation.json'
    if json_object(read_protected_artifact(record_path, fixture, hashlib.sha256(
            (json.dumps(invocation.identity, indent=2) + '\n').encode()).hexdigest())) != invocation.identity:
        raise ValueError('invocation record changed')
    if require_session:
        if invocation.command_sha256 is None:
            raise ValueError('invocation launch was not claimed')
        read_protected_artifact(invocation.artifact_root / 'command.json', fixture, invocation.command_sha256)
        session_path = invocation.artifact_root / 'session.json'
        expected = {'invocation_sha256': invocation.sha256, 'session_id': invocation.session_id,
                    'command_sha256': invocation.command_sha256}
        digest = hashlib.sha256((json.dumps(expected, sort_keys=True) + '\n').encode()).hexdigest()
        if invocation.session_id is None or json_object(read_protected_artifact(session_path, fixture, digest)) != expected:
            raise ValueError('invocation has no host-bound native session')


def claim_launch(invocation: Invocation, command: tuple[str, ...]) -> Invocation:
    from evals.native_runtime import build_exec_command, build_review_command, worker_prompt
    verify_invocation(invocation.fixture, invocation)
    if invocation.session_id is not None or invocation.command_sha256 is not None:
        raise ValueError('invocation launch is already claimed')
    builder = build_exec_command if invocation.kind == 'worker' else build_review_command
    options = {'writable': True} if invocation.kind == 'worker' else {}
    prefix = builder(invocation.execution_root, model=invocation.model, invocation=invocation, **options)
    if len(command) != len(prefix) + 1 or tuple(command[:-1]) != prefix or \
            not isinstance(command[-1], str) or not command[-1].strip() or \
            (invocation.kind == 'worker' and command[-1] != worker_prompt(invocation)):
        raise ValueError('launch command does not match its invocation')
    return _claim_command(invocation, command)


def claim_native_launch(invocation: Invocation, command: tuple[str, ...], *, binary, disabled_servers: tuple[str, ...]) -> Invocation:
    from evals.native_session import build_session_command
    verify_invocation(invocation.fixture, invocation)
    expected = build_session_command(invocation.execution_root, binary=binary, disabled_servers=disabled_servers,
                                     writable=invocation.kind == 'worker', invocation=invocation)
    if command != expected:
        raise ValueError('native launch command does not match its invocation')
    return _claim_command(invocation, command)


def _claim_command(invocation: Invocation, command: tuple[str, ...]) -> Invocation:
    if invocation.session_id is not None or invocation.command_sha256 is not None:
        raise ValueError('invocation launch is already claimed')
    raw = json.dumps(list(command)).encode()
    # Claim before spawning; a failed spawn still cannot reuse this invocation.
    try:
        with (invocation.artifact_root / 'command.json').open('xb') as stream:
            stream.write(raw)
    except FileExistsError as error:
        raise ValueError('invocation launch is already claimed') from error
    return replace(invocation, command_sha256=hashlib.sha256(raw).hexdigest())


def bind_session(invocation: Invocation, session_id: str) -> Invocation:
    verify_invocation(invocation.fixture, invocation)
    if invocation.session_id is not None:
        raise ValueError('invocation session is already bound')
    if invocation.command_sha256 is None:
        raise ValueError('claim the invocation launch before binding a session')
    read_protected_artifact(invocation.artifact_root / 'command.json', invocation.fixture, invocation.command_sha256)
    try:
        if str(UUID(session_id)) != session_id:
            raise ValueError('noncanonical session')
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError('invalid native session identity') from error
    record = {'invocation_sha256': invocation.sha256, 'session_id': session_id,
              'command_sha256': invocation.command_sha256}
    try:
        with (invocation.artifact_root / 'session.json').open('x') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')
    except FileExistsError as error:
        raise ValueError('invocation session is already bound') from error
    return replace(invocation, session_id=session_id)


def consume_invocation(fixture: RuntimeFixture, invocation: Invocation) -> None:
    verify_invocation(fixture, invocation, require_session=True)
    # Atomic host-owned marker prevents concurrent or repeated grading of this launch.
    try:
        with (invocation.artifact_root / 'consumed.json').open('x') as stream:
            stream.write(json.dumps({'invocation_sha256': invocation.sha256}) + '\n')
    except FileExistsError as error:
        raise ValueError('invocation evidence was already consumed') from error
