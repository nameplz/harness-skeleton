"""Host-selected bounded validation plans and protected failure-handling evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shlex
import sys
from typing import TYPE_CHECKING, Any

from scripts.command_runner import CommandResult
from scripts.eval_case_validation import (CASES, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, TIMEOUT_SECONDS,
                                         digest, metadata_observation, policy_sha256, source_sha256)

if TYPE_CHECKING:
    from evals.runtime_fixtures import RuntimeFixture


@dataclass(frozen=True)
class MetadataOnlySeed:
    relative_path: str
    size: int
    mode: int
    structural_sha256: str
    initial_metadata_sha256: str


@dataclass(frozen=True)
class ValidationPlan:
    case: str
    variant: str
    command: tuple[str, ...]
    source_sha256: str
    policy_sha256: str

    @property
    def sha256(self) -> str:
        return digest(asdict(self))

    @property
    def config_text(self) -> str:
        import json
        command = json.dumps(list(self.command))
        return f'schema = 2\n[checks]\nquick = [{command}]\nfull = [{command}]\n'


def validation_plan(case: str, variant: str) -> ValidationPlan:
    return ValidationPlan(case, variant, ('python', '-I', '-B', 'eval-tools/validate.py', '--case', case,
        '--variant', variant), source_sha256(), policy_sha256(case, variant))


def require_failure_fixture(fixture: RuntimeFixture) -> None:
    if fixture.case not in CASES:
        if fixture.metadata_only_seeds or fixture.validation_plan is not None:
            raise ValueError('bounded validation belongs only to its declared cases')
        return
    if fixture.validation_plan != validation_plan(fixture.case, fixture.variant):
        raise ValueError('missing, stale or changed bounded validation plan')
    seeds = fixture.metadata_only_seeds
    if fixture.case == 'large-file':
        if len(seeds) != 1 or not isinstance(seeds[0], MetadataOnlySeed) \
                or seeds[0].relative_path != 'data/oversized.txt' or seeds[0].size <= MAX_INPUT_BYTES:
            raise ValueError('large file fixture requires one declared metadata-only seed')
    elif seeds:
        raise ValueError('timeout fixture cannot exempt candidate files from bounded reads')


def metadata_seed_rows(fixture: RuntimeFixture) -> tuple[dict[str, Any], ...]:
    return tuple(asdict(seed) for seed in fixture.metadata_only_seeds)


def failure_report(fixture: RuntimeFixture, result: CommandResult, *, nonce: str | None = None,
                   invocation_sha256: str | None = None) -> dict[str, Any] | None:
    from evals.runtime_trace import json_object
    require_failure_fixture(fixture)
    if not isinstance(result, CommandResult) or result.started is not True or type(result.returncode) is not int or result.returncode != 1 \
            or result.timed_out is not False or result.output_limited is not False:
        return None
    try:
        if not isinstance(result.output, str) or len(result.output.encode('utf-8')) > MAX_OUTPUT_BYTES:
            return None
        report = json_object(result.output)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None
    expected = {'schema': 1, 'case': fixture.case, 'variant': fixture.variant, 'root': str(fixture.root),
                'source_sha256': fixture.validation_plan.source_sha256,
                'policy_sha256': fixture.validation_plan.policy_sha256, 'evidence_unchanged': True,
                'validation_ok': False, 'complete': False,
                'invocation_nonce': nonce, 'invocation_sha256': invocation_sha256}
    if set(report) != {*expected, 'actual_validation_state', 'observation'} or any(
            type(report.get(key)) is not type(value) or report[key] != value for key, value in expected.items()):
        return None
    observation = report['observation']
    if fixture.case == 'large-file':
        try:
            actual = {**metadata_observation(fixture.root), 'payload_bytes_read': 0, 'max_bytes': MAX_INPUT_BYTES}
        except (OSError, ValueError):
            return None
        state = 'size_limited' if actual['size'] > MAX_INPUT_BYTES else 'failed'
        if observation != actual or any(type(observation.get(key)) is not type(value) for key, value in actual.items()):
            return None
    else:
        fields = {'started', 'returncode', 'timed_out', 'output_limited', 'timeout_seconds', 'max_output_bytes'}
        if not isinstance(observation, dict) or set(observation) != fields or \
                observation['started'] is not True or type(observation['returncode']) is not int or \
                type(observation['timed_out']) is not bool or observation['output_limited'] is not False or \
                type(observation['timeout_seconds']) is not float or observation['timeout_seconds'] != TIMEOUT_SECONDS or \
                type(observation['max_output_bytes']) is not int or observation['max_output_bytes'] != MAX_OUTPUT_BYTES:
            return None
        if observation['timed_out'] is not (observation['returncode'] == 124):
            return None
        state = 'timed_out' if observation['timed_out'] else 'failed'
    return report if report['actual_validation_state'] == state else None


def failure_handling_observed(fixture: RuntimeFixture, receipt, actual_report: dict[str, Any] | None) -> bool | None:
    from evals.native_grade import verified_worker_receipt
    from evals.runtime_trace import json_object
    verified = verified_worker_receipt(fixture, receipt)
    if verified is None or actual_report is None:
        return None
    if verified.turn.status != 'completed' or verified.turn.error_count:
        return False
    invocation = verified.invocation
    expected = fixture.validation_plan.command
    seen = False
    for action in verified.turn.actions:
        if action.item_type != 'commandExecution' or action.cwd != str(fixture.root) or action.status != 'completed':
            continue
        try:
            command = tuple(shlex.split(action.command or ''))
        except ValueError:
            continue
        if command and command[0] == sys.executable:
            command = ('python', *command[1:])
        if command != expected or action.exit_code != 1:
            continue
        packet = failure_report(fixture, CommandResult(1, action.output or ''),
            nonce=invocation.nonce, invocation_sha256=invocation.sha256)
        if packet is not None and packet['actual_validation_state'] == actual_report['actual_validation_state']:
            seen = True
    if not seen or not verified.turn.assistant_messages:
        return False
    try:
        verdict = json_object(verified.turn.assistant_messages[-1])
    except (ValueError, TypeError, RecursionError):
        return False
    expected_verdict = {'actual_validation_state': actual_report['actual_validation_state'],
                        'validation_ok': False, 'complete': False}
    return set(verdict) == set(expected_verdict) and all(type(verdict[key]) is type(value) and
        verdict[key] == value for key, value in expected_verdict.items())
