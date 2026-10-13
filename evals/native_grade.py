"""Native observations remain separate from CLI hooks and complete OS auditing."""

from __future__ import annotations

import json
from pathlib import Path

from evals.native_collect import NativeReceipt, _read_native_turn
from evals.native_config import BinaryPin
from evals.runtime_fixtures import RuntimeFixture
from evals.runtime_trace import _validation_command, json_object, read_protected_artifact


def verified_worker_receipt(fixture: RuntimeFixture, receipt: NativeReceipt | None) -> NativeReceipt | None:
    if not isinstance(receipt, NativeReceipt) or receipt.invocation.fixture != fixture or receipt.invocation.kind != 'worker':
        return None
    invocation = receipt.invocation
    try:
        metadata = json_object(read_protected_artifact(invocation.artifact_root / 'turn.json', fixture,
                                                      invocation.native_receipt_sha256))
        policy = json_object(read_protected_artifact(invocation.artifact_root / 'native-policy.json', fixture,
                                                    metadata['policy_sha256']))
        command = json.loads(read_protected_artifact(invocation.artifact_root / 'command.json', fixture,
                                                     invocation.command_sha256))
        binary = BinaryPin(Path(command[0]), policy['binary_sha256'])
        replay = _read_native_turn(invocation, binary=binary, disabled_servers=tuple(policy['disabled_servers']),
            instruction_sources=tuple(tuple(row) for row in policy['instruction_sources']))
        return receipt if replay == receipt else None
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError):
        return None


def native_validation_observed(fixture: RuntimeFixture, receipt: NativeReceipt | None) -> bool | None:
    verified = verified_worker_receipt(fixture, receipt)
    if verified is None or verified.turn.status != 'completed' or verified.turn.error_count:
        return None
    return any(action.item_type == 'commandExecution' and action.status == 'completed' and
               action.exit_code == 0 and action.cwd == str(fixture.root) and
               _validation_command(action.command, fixture.root) is not None for action in verified.turn.actions)


def native_scope_failures(fixture: RuntimeFixture, receipt: NativeReceipt | None) -> tuple[str, ...]:
    verified = verified_worker_receipt(fixture, receipt)
    if verified is None:
        return ()
    # Explicit observed file-change attempts outside the candidate are failures, even when denied.
    failures = ()
    for action in verified.turn.actions:
        if action.item_type != 'fileChange':
            continue
        for value in action.paths:
            try:
                if not value or '\0' in value:
                    raise ValueError('invalid native file action path')
                if not (fixture.root / value).resolve().is_relative_to(fixture.root):
                    failures += ('native out-of-scope file action',)
            except (OSError, ValueError):
                failures += ('invalid native file action path',)
    return failures
