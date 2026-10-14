"""Host-bound native review of a fixed, externally protected read-only snapshot."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from evals.runtime_cases import case_spec
from evals.native_config import BinaryPin
from evals.native_runtime import worker_prompt
from evals.runtime_fixtures import RuntimeFixture
from evals.runtime_invocation import Invocation, consume_invocation, verify_invocation
from evals.runtime_review import ReviewEvidence, _scan, final_manifest, review_prompt


@dataclass(frozen=True)
class ReviewBindings:
    final_manifest_sha256: str
    config_sha256: str
    suite_sha256: str
    source_sha256: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
               for value in self.as_dict().values()):
            raise ValueError('review bindings must be canonical SHA-256 values')

    def as_dict(self) -> dict[str, str]:
        return {'final_manifest_sha256': self.final_manifest_sha256, 'config_sha256': self.config_sha256,
                'suite_sha256': self.suite_sha256, 'source_sha256': self.source_sha256}


@dataclass(frozen=True)
class NativeReviewRequest:
    invocations: tuple[Invocation, ...]
    bindings: ReviewBindings
    binary: BinaryPin
    disabled_servers: tuple[str, ...] = ()
    instruction_sources: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.invocations, tuple) or not 1 <= len(self.invocations) <= 2 or any(
                not isinstance(launch, Invocation) for launch in self.invocations) or \
                not isinstance(self.bindings, ReviewBindings) or not isinstance(self.binary, BinaryPin):
            raise ValueError('native review request needs protected launches, bindings and binary pin')


def canonical_prompt(invocation: Invocation, bindings: ReviewBindings | None = None) -> str:
    if invocation.kind == 'worker':
        if bindings is not None:
            raise ValueError('worker input cannot contain review bindings')
        return worker_prompt(invocation)
    if invocation.kind not in {'correctness', 'security'} or not isinstance(bindings, ReviewBindings) or \
            invocation.final_manifest_sha256 != bindings.final_manifest_sha256 or \
            invocation.source.source_sha256 != bindings.source_sha256:
        raise ValueError('review prompt differs from its invocation bindings')
    return review_prompt(invocation.fixture, invocation.kind, bindings.as_dict(), invocation=invocation)


def verify_review_snapshot(invocation: Invocation, bindings: ReviewBindings) -> dict:
    canonical_prompt(invocation, bindings)
    verify_invocation(invocation.fixture, invocation)
    manifest = final_manifest(invocation.fixture)
    snapshot = invocation.execution_root
    from evals.runtime_boundary import require_disjoint, fixture_protection
    require_disjoint(fixture_protection(invocation.fixture), snapshot)
    if manifest['sha256'] != bindings.final_manifest_sha256 or snapshot.is_relative_to(invocation.fixture.root):
        raise ValueError('review candidate or external snapshot changed')
    expected = [{**row, 'mode': row['mode'] & ~0o222} for row in manifest['files']]
    if list(_scan(snapshot)) != expected or any(Path(directory).stat().st_mode & 0o222
                                               for directory, _, _ in os.walk(snapshot)):
        raise ValueError('review snapshot contents or read-only modes changed')
    return manifest


def _verdict(receipt, bindings: ReviewBindings) -> tuple[str, str]:
    from evals.runtime_trace import json_object
    invocation, turn = receipt.invocation, receipt.turn
    if turn.status != 'completed' or turn.error_count or not turn.assistant_messages:
        raise ValueError('native review did not finish with a verdict')
    verdict = json_object(turn.assistant_messages[-1])
    expected = {**bindings.as_dict(), 'role': invocation.kind, 'invocation_nonce': invocation.nonce,
                'invocation_sha256': invocation.sha256, 'source_manifest_sha256': invocation.source.manifest_sha256}
    if set(verdict) != {*expected, 'status'} or any(verdict[key] != value for key, value in expected.items()) or \
            not isinstance(verdict['status'], str) or verdict['status'] not in {'pass', 'fail', 'unknown'}:
        raise ValueError('native verdict differs from current review bindings')
    return invocation.kind, verdict['status']


def load_native_review_evidence(fixture: RuntimeFixture, invocations: tuple[Invocation, ...], *, binary: BinaryPin,
                               bindings: ReviewBindings, disabled_servers: tuple[str, ...] = (),
                               instruction_sources: tuple[tuple[str, str], ...] = ()) -> ReviewEvidence:
    from evals.native_collect import _read_native_turn
    required = set(case_spec(fixture.case).required_review_roles)
    if not isinstance(invocations, tuple) or len(invocations) != len(required) or any(
            not isinstance(launch, Invocation) or launch.fixture != fixture for launch in invocations):
        raise ValueError('native review needs its exact parent-issued launches')
    roles = tuple(launch.kind for launch in invocations)
    if set(roles) != required or len(set(roles)) != len(roles) or \
            len({launch.session_id for launch in invocations}) != len(invocations) or \
            len({launch.execution_root for launch in invocations}) != 1:
        raise ValueError('native review roles, sessions or snapshots are not independent and fixed')
    receipts = tuple(_read_native_turn(launch, binary=binary, disabled_servers=disabled_servers,
        instruction_sources=instruction_sources, review_bindings=bindings) for launch in invocations)
    statuses = tuple(sorted(_verdict(receipt, bindings) for receipt in receipts))
    manifests = tuple(verify_review_snapshot(launch, bindings) for launch in invocations)
    manifest = manifests[0]
    if any(row != manifest for row in manifests) or final_manifest(fixture) != manifest:
        raise ValueError('candidate changed while reading native reviews')
    digest = hashlib.sha256(json.dumps({'bindings': bindings.as_dict(), 'receipts': sorted(
        (receipt.invocation.kind, receipt.invocation.sha256, receipt.invocation.native_receipt_sha256)
        for receipt in receipts)}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    # Validate every launch before consuming any. No failed/stale verdict can consume another role.
    for launch in invocations:
        if (launch.artifact_root / 'consumed.json').exists() or (launch.artifact_root / 'consumed.json').is_symlink():
            raise ValueError('native review was already consumed')
    for launch in invocations:
        consume_invocation(fixture, launch)
    return ReviewEvidence(fixture.case, fixture.condition, fixture.seed_head, manifest['seed_manifest_sha256'],
        manifest['sha256'], bindings.config_sha256, bindings.suite_sha256, bindings.source_sha256, digest, statuses)
