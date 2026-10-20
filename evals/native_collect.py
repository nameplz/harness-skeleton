"""Host-owned, one-use collection of an actual same-process native turn."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from contextlib import ExitStack
import hashlib
import json
import re
import os
from pathlib import Path
from uuid import uuid4

from evals.native_config import BinaryPin, verify_binary
from evals.native_review import ReviewBindings, canonical_prompt, verify_review_snapshot
from evals.native_session import _uuid, build_session_command, native_session
from evals.native_telemetry import validate_account
from evals.native_turn import DELTAS, TurnCollector, TurnEvidence, _integer
from evals.runtime_invocation import Invocation, consume_invocation, verify_invocation
from evals.runtime_trace import json_object, read_host_artifact, read_protected_artifact
from evals.runtime_remote import (RemoteBinding, remote_tools, write_remote_receipt,
                                 load_remote_receipt)
from evals.native_dynamic import (begin_dynamic, dynamic_item, dynamic_request,
    dynamic_response_sent, finish_dynamic)
from evals.runtime_access import require_profile, host_output, write_host_file
from evals.native_lifecycle import lifecycle_record, verify_lifecycle
from scripts.command_runner import _command_environment

ACCOUNTS = frozenset({'account/updated', 'account/rateLimits/updated'})
TURN_METHODS = frozenset({'turn/started', 'turn/completed', 'item/started', 'item/completed',
                         'thread/tokenUsage/updated', 'error', *DELTAS})
BOOKKEEPING = frozenset({'thread/status/changed', 'thread/closed'})
REQUEST_ID = 100


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


def native_guidance(invocation: Invocation) -> str:
    if invocation.kind != 'worker' or invocation.fixture.condition == 'baseline':
        return ''
    from evals.runtime_fixtures import PROJECT_ROOT
    return '\n\n'.join((PROJECT_ROOT / path).read_text() for path in
                        ('AGENTS.md', '.agents/skills/harness/SKILL.md'))


def _policy(invocation: Invocation, binary: BinaryPin, servers: tuple[str, ...], client: str,
            instructions: tuple[tuple[str, str], ...], bindings: ReviewBindings | None = None) -> dict:
    if not isinstance(instructions, tuple) or len(instructions) > 128 or any(
        not isinstance(row, tuple) or len(row) != 2 or any(not isinstance(v, str) or
        not re.fullmatch(r'[0-9a-f]{64}', v) for v in row) for row in instructions) or \
            len({row[0] for row in instructions}) != len(instructions):
        raise ValueError('invalid host instruction source allowlist')
    policy = {'schema': 1, 'execution_profile': invocation.fixture.execution_profile,
            'invocation_sha256': invocation.sha256, 'source_sha256': invocation.source.source_sha256,
            'binary_sha256': binary.sha256, 'disabled_servers': list(servers), 'request_id': REQUEST_ID,
            'client_id': client, 'prompt_sha256': _sha(canonical_prompt(invocation, bindings).encode()),
            'review_bindings': bindings.as_dict() if bindings is not None else None,
            'instruction_sources': [list(row) for row in instructions],
            'environment_sha256': _sha(json.dumps(_command_environment(), sort_keys=True).encode()),
            'guidance_sha256': _sha(native_guidance(invocation).encode())}
    if invocation.fixture.remote_context is not None:
        context = invocation.fixture.remote_context
        policy['remote'] = {'context_sha256': context.structural_sha256,
            'binding_sha256': context.binding_sha256, 'protocol_sha256': context.protocol_sha256,
            'source_sha256': context.source_sha256,
            'dynamic_tools': remote_tools(context) if invocation.kind == 'worker' else []}
    return policy


@dataclass(frozen=True)
class NativeReceipt:
    invocation: Invocation
    turn: TurnEvidence
    rpc_in_sha256: str
    rpc_out_sha256: str
    policy_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    environment_sha256: str
    session_json: str
    telemetry: tuple[tuple[str, int], ...]
    returncode: int
    process_tree_cleanup_verified: bool = False
    dynamic_json: str | None = None
    supervisor_receipt_sha256: str | None = None


class _Dispatch:
    def __init__(self, thread: str, root: Path, prompt: str, client: str, invocation: Invocation | None = None):
        self.invocation = invocation
        self.remote_context = (invocation.fixture.remote_context if invocation is not None
                               and invocation.kind == 'worker' else None)
        tools = tuple(row['name'] for row in remote_tools(self.remote_context)) if self.remote_context else ()
        self.collector = TurnCollector(thread, root, prompt, dynamic_tools=tools)
        self.dynamic = None
        self.callback_replay = None
        self.client = client
        self.pending: tuple[dict, ...] = ()
        self.telemetry: tuple[tuple[str, int], ...] = ()
        self.closed = False
        self.count = 0

    def notification(self, message: dict) -> None:
        self.count += 1
        if self.count > 10000 or 'id' in message or set(message) - {'method', 'params', 'emittedAtMs'} or \
                'emittedAtMs' in message and not _integer(message['emittedAtMs']):
            raise ValueError('invalid native notification envelope')
        method, params = message.get('method'), message.get('params')
        if not isinstance(method, str) or not isinstance(params, dict):
            raise ValueError('invalid native notification')
        if method in ACCOUNTS:
            validate_account(method, params)
            counts = dict(self.telemetry)
            self.telemetry = tuple(sorted({**counts, method: counts.get(method, 0) + 1}.items()))
            return
        if params.get('threadId') != self.collector.thread_id or self.closed:
            raise ValueError('native notification belongs to another or closed thread')
        if method in BOOKKEEPING:
            self._bookkeeping(method, params)
        elif method in TURN_METHODS:
            if self.collector.bound:
                self._turn_event(message)
            else:
                self.pending += (message,)
        else:
            raise ValueError('unexpected native capability')

    def _bookkeeping(self, method: str, params: dict) -> None:
        if method == 'thread/closed':
            if self.collector.status is None or set(params) != {'threadId'}:
                raise ValueError('premature native closure')
            self.closed = True
            return
        status = params.get('status')
        if set(params) != {'threadId', 'status'} or not isinstance(status, dict) or \
                status not in ({'type': 'active', 'activeFlags': []}, {'type': 'idle'}):
            raise ValueError('unknown native thread status')

    def _turn_event(self, message: dict) -> None:
        item = message['params'].get('item')
        if isinstance(item, dict) and item.get('type') == 'userMessage' and item.get('clientId') != self.client:
            raise ValueError('native user message differs from request identity')
        is_dynamic = isinstance(item, dict) and item.get('type') == 'dynamicToolCall'
        if is_dynamic:
            if self.dynamic is None:
                raise ValueError('native dynamic item has no bound remote capability')
            self.dynamic = dynamic_item(self.dynamic, message)
        self.collector.notification(message)
        if message['method'] == 'turn/started' and self.remote_context is not None:
            if self.dynamic is not None:
                raise ValueError('native remote turn was already bound')
            invocation = self.invocation
            binding = RemoteBinding(invocation.nonce, invocation.sha256, invocation.source.source_sha256,
                invocation.session_id, self.collector.thread_id, self.collector.turn_id)
            self.dynamic = begin_dynamic(self.remote_context, binding)
        if is_dynamic and message['method'] == 'item/started' and self.callback_replay is not None:
            self.callback_replay(self)

    def server_request(self, raw: bytes, send) -> None:
        if self.dynamic is None or not self.collector.bound or self.collector.status is not None or self.closed:
            raise ValueError('native callback lacks a current remote worker turn')
        updated, response = dynamic_request(self.dynamic, raw)
        send(response)
        self.dynamic = dynamic_response_sent(updated, response)

    def response(self, message: dict) -> None:
        if set(message) != {'id', 'result'} or type(message['id']) is not int or message['id'] != REQUEST_ID:
            raise ValueError('native response differs from request identity')
        self.collector.bind_response(message['result'])
        for event in self.pending:
            self._turn_event(event)
        self.pending = ()


def _pop(exchange) -> dict:
    _, message = _pop_raw(exchange)
    return message


def _pop_raw(exchange) -> tuple[bytes, dict]:
    while b'\n' not in exchange.buffer:
        exchange.pump()
    raw, _, tail = exchange.buffer.partition(b'\n')
    exchange.buffer = bytearray(tail)
    return bytes(raw) + b'\n', exchange.decode(bytes(raw))


def collect_native_turn(invocation: Invocation, *, binary: BinaryPin,
                        disabled_servers: tuple[str, ...] = (), timeout_seconds: float = 300,
                        max_output_bytes: int = 1024 * 1024,
                        instruction_sources: tuple[tuple[str, str], ...] = (),
                        review_bindings: ReviewBindings | None = None) -> NativeReceipt:
    supervised = require_profile(invocation.fixture.execution_profile)
    verify_invocation(invocation.fixture, invocation)
    bindings = review_bindings
    canonical_prompt(invocation, bindings)
    if invocation.kind != 'worker':
        verify_review_snapshot(invocation, bindings)
    client = str(uuid4())
    policy = _json(_policy(invocation, binary, disabled_servers, client, instruction_sources, bindings))
    root = invocation.artifact_root
    try:
        write_host_file(root / 'native-policy.json', policy, invocation.fixture.execution_profile)
    except FileExistsError:
        raise ValueError('native invocation was already attempted') from None
    request = {'id': REQUEST_ID, 'method': 'turn/start', 'params': {
        'threadId': None, 'clientUserMessageId': client,
        'input': [{'type': 'text', 'text': canonical_prompt(invocation, bindings), 'text_elements': []}]}}
    with host_output(root / 'rpc.in.jsonl', invocation.fixture.execution_profile) as incoming:
        with native_session(invocation.execution_root, binary=binary, model=invocation.model,
                writable=invocation.kind == 'worker', disabled_servers=disabled_servers, timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes, invocation=invocation,
                developer_instructions=native_guidance(invocation), supervised=supervised) as (exchange, session):
            if session.instruction_sources != instruction_sources:
                raise ValueError('native instructions differ from host-approved sources')
            dispatch = _run_turn(exchange, session.thread_id, invocation, client, request, incoming, bindings)
        turn = dispatch.collector.result()  # Includes notifications drained during shutdown.
    verify_invocation(invocation.fixture, exchange.invocation, require_session=True)
    if invocation.kind != 'worker':
        verify_review_snapshot(exchange.invocation, bindings)
    return _seal(exchange, session, dispatch, turn, policy)


def _run_turn(exchange, thread_id: str, invocation: Invocation, client: str, request: dict, incoming, bindings: ReviewBindings | None) -> _Dispatch:
    with ExitStack() as stack:
        streams = None
        if invocation.kind == 'worker' and invocation.fixture.remote_context is not None:
            streams = tuple(stack.enter_context(host_output(invocation.artifact_root / name,
                invocation.fixture.execution_profile))
                for name in ('dynamic-rpc.in.jsonl', 'dynamic-rpc.out.jsonl'))
        return _exchange_turn(exchange, thread_id, invocation, client, request, incoming, bindings, streams)


def _exchange_turn(exchange, thread_id, invocation, client, request, incoming, bindings, streams):
    root = invocation.artifact_root
    dispatch = _Dispatch(thread_id, invocation.execution_root, canonical_prompt(invocation, bindings), client,
                         exchange.invocation)
    dynamic_bytes = (0, 0)
    def dynamic_write(index: int, raw: bytes) -> None:
        nonlocal dynamic_bytes
        if streams is None or len(raw) > 65536 or dynamic_bytes[index] + len(raw) > 65536:
            raise ValueError('native dynamic transport exceeded its capability or byte limit')
        streams[index].write(raw)
        streams[index].flush()
        dynamic_bytes = tuple(value + len(raw) if position == index else value
                              for position, value in enumerate(dynamic_bytes))
    def capture(raw: bytes, message: dict) -> None:
        # Account/config payloads stay private. This file is a filtered turn transport log.
        if 'method' not in message or message.get('method') in TURN_METHODS | BOOKKEEPING:
            incoming.write(raw + b'\n')
            incoming.flush()
        elif message.get('method') == 'item/tool/call':
            dynamic_write(0, raw + b'\n')
    def send_response(raw: bytes) -> None:
        exchange.send_callback(raw)
        dynamic_write(1, raw)
    exchange.raw_handler, exchange.turn_handler = capture, dispatch.notification
    exchange.stage = 'turn/run'
    request = {**request, 'params': {**request['params'], 'threadId': thread_id}}
    request_raw = (json.dumps(request) + '\n').encode()
    if len(request_raw) > 65536:
        raise ValueError('native turn request exceeded its byte limit')
    write_host_file(root / 'rpc.out.jsonl', request_raw, invocation.fixture.execution_profile)
    exchange.send_turn(request_raw)
    while not dispatch.collector.bound or dispatch.collector.status is None:
        raw, message = _pop_raw(exchange)
        if 'method' in message and 'id' in message:
            dispatch.server_request(raw, send_response)
        elif 'method' in message:
            dispatch.notification(message)
        else:
            dispatch.response(message)
    dispatch.collector.result()
    return dispatch


def _seal(exchange, session, dispatch: _Dispatch, turn: TurnEvidence, policy: bytes) -> NativeReceipt:
    root = exchange.invocation.artifact_root
    if exchange.environment_sha256 != json_object(policy.decode())['environment_sha256']:
        raise ValueError('native launch environment changed')
    metadata = {'schema': 1, 'policy_sha256': _sha(policy),
        'rpc_in_sha256': _sha(read_host_artifact(root / 'rpc.in.jsonl', exchange.invocation.fixture)),
        'rpc_out_sha256': _sha(read_host_artifact(root / 'rpc.out.jsonl', exchange.invocation.fixture, max_bytes=65536)),
        'turn_sha256': _sha(_json(asdict(turn))),
        'stdout_sha256': exchange.digests[0].hexdigest(), 'stderr_sha256': exchange.digests[1].hexdigest(),
        'stdout_bytes': exchange.counts[0], 'stderr_bytes': exchange.counts[1],
        'environment_sha256': exchange.environment_sha256, 'session': asdict(session), 'telemetry': dispatch.telemetry,
        'binary_identity': exchange.binary_identity,
        'returncode': exchange.process.returncode, 'process_tree_cleanup_verified': False}
    dynamic = finish_dynamic(dispatch.dynamic) if dispatch.dynamic is not None else None
    if dynamic is not None:
        metadata['dynamic'] = _seal_dynamic(exchange.invocation, dispatch, dynamic)
    if require_profile(exchange.invocation.fixture.execution_profile):
        lifecycle = lifecycle_record(exchange.process, _lifecycle_bindings(exchange.invocation, metadata))
        protected = _json(lifecycle)
        write_host_file(root / 'supervisor.json', protected, exchange.invocation.fixture.execution_profile)
        metadata['supervisor_receipt_sha256'] = _sha(protected)
        recorded = json_object(read_protected_artifact(root / 'supervisor.json', exchange.invocation.fixture, _sha(protected)))
        verify_lifecycle(recorded, _lifecycle_bindings(exchange.invocation, metadata), returncode=metadata['returncode'])
    raw = _json(metadata)
    write_host_file(root / 'turn.json', raw, exchange.invocation.fixture.execution_profile)
    bound = replace(exchange.invocation, native_receipt_sha256=_sha(raw))
    return _receipt(bound, turn, metadata, dynamic)


def _receipt(invocation: Invocation, turn: TurnEvidence, data: dict, dynamic=None) -> NativeReceipt:
    return NativeReceipt(invocation, turn, data['rpc_in_sha256'], data['rpc_out_sha256'], data['policy_sha256'],
        data['stdout_sha256'], data['stderr_sha256'], data['stdout_bytes'], data['stderr_bytes'],
        data['environment_sha256'], json.dumps(data['session'], sort_keys=True),
        tuple(tuple(row) for row in data['telemetry']), data['returncode'], data['process_tree_cleanup_verified'],
        json.dumps(asdict(dynamic), sort_keys=True) if dynamic is not None else None,
        data.get('supervisor_receipt_sha256'))


def _lifecycle_bindings(invocation: Invocation, metadata: dict) -> dict:
    session = read_host_artifact(invocation.artifact_root / 'session.json', invocation.fixture)
    policy = json_object(read_protected_artifact(invocation.artifact_root / 'native-policy.json',
                                               invocation.fixture, metadata['policy_sha256']))
    return {'invocation_sha256': invocation.sha256, 'source_sha256': invocation.source.source_sha256,
        'command_sha256': invocation.command_sha256, 'session_sha256': _sha(session),
        'policy_sha256': metadata['policy_sha256'], 'turn_sha256': metadata['turn_sha256'],
        'environment_sha256': metadata['environment_sha256'], 'binary_sha256': policy['binary_sha256']}


def _seal_dynamic(invocation: Invocation, dispatch: _Dispatch, evidence) -> dict:
    root, fixture = invocation.artifact_root, invocation.fixture
    if evidence.declaration_sha256 != fixture.remote_context.protocol_sha256:
        raise ValueError('native dynamic declaration changed')
    receipt = write_remote_receipt(dispatch.dynamic.remote, root / 'remote-receipt.json')
    if receipt != evidence.remote_receipt:
        raise ValueError('native remote receipt differs from lifecycle')
    raw = _json(asdict(evidence))
    if len(raw) > 1024 * 1024:
        raise ValueError('native dynamic evidence exceeded its limit')
    write_host_file(root / 'dynamic.json', raw, fixture.execution_profile)
    return {'evidence_sha256': _sha(raw), 'remote_receipt_sha256': receipt.sha256,
            'rpc_in_sha256': _sha(read_host_artifact(root / 'dynamic-rpc.in.jsonl', fixture, max_bytes=65536)),
            'rpc_out_sha256': _sha(read_host_artifact(root / 'dynamic-rpc.out.jsonl', fixture, max_bytes=65536))}


def _replay_callbacks(invocation: Invocation, metadata: dict, dispatch: _Dispatch):
    if dispatch.remote_context is None:
        if metadata.get('dynamic') is not None:
            raise ValueError('native dynamic evidence belongs only to remote workers')
        return lambda: None
    data = metadata.get('dynamic')
    if not isinstance(data, dict) or set(data) != {'evidence_sha256', 'remote_receipt_sha256',
                                                 'rpc_in_sha256', 'rpc_out_sha256'}:
        raise ValueError('native dynamic evidence bindings unavailable')
    root, fixture = invocation.artifact_root, invocation.fixture
    raw = []
    for name, key in (('dynamic-rpc.in.jsonl', 'rpc_in_sha256'), ('dynamic-rpc.out.jsonl', 'rpc_out_sha256')):
        value = read_host_artifact(root / name, fixture, max_bytes=65536)
        if _sha(value) != data[key]:
            raise ValueError('native dynamic transport digest changed')
        raw.append(value.splitlines(keepends=True))
    if not raw[0] or len(raw[0]) != len(raw[1]) or len(raw[0]) > 16:
        raise ValueError('native dynamic transport is incomplete or unbounded')
    pairs = tuple(zip(*raw))
    position = 0
    def callback(current):
        nonlocal position
        if position >= len(pairs):
            raise ValueError('native dynamic lifecycle exceeds recorded transport')
        request, expected_response = pairs[position]
        def sent(response):
            if response != expected_response:
                raise ValueError('native dynamic response bytes differ from recorded writes')
        current.server_request(request, sent)
        position += 1
    dispatch.callback_replay = callback
    def finish():
        if position != len(pairs) or dispatch.dynamic is None:
            raise ValueError('native dynamic transport was not fully consumed')
        evidence = finish_dynamic(dispatch.dynamic)
        original = read_protected_artifact(root / 'dynamic.json', fixture, data['evidence_sha256'])
        if original.encode() != _json(asdict(evidence)):
            raise ValueError('native dynamic evidence differs from raw transport replay')
        receipt = load_remote_receipt(fixture.remote_context, dispatch.dynamic.binding,
                                     root / 'remote-receipt.json', data['remote_receipt_sha256'])
        if receipt != evidence.remote_receipt:
            raise ValueError('native remote receipt differs from replay')
        return evidence
    return finish


def _read_native_turn(invocation: Invocation, *, binary: BinaryPin,
                     disabled_servers: tuple[str, ...] = (),
                     instruction_sources: tuple[tuple[str, str], ...] = (),
                     review_bindings: ReviewBindings | None = None) -> NativeReceipt:
    supervised = require_profile(invocation.fixture.execution_profile)
    bindings = review_bindings
    canonical_prompt(invocation, bindings)
    if invocation.kind != 'worker':
        verify_review_snapshot(invocation, bindings)
    verify_invocation(invocation.fixture, invocation, require_session=True)
    verify_binary(binary)
    root, fixture = invocation.artifact_root, invocation.fixture
    if invocation.native_receipt_sha256 is None:
        raise ValueError('native receipt has no external digest binding')
    data = json_object(read_protected_artifact(root / 'turn.json', fixture, invocation.native_receipt_sha256))
    from evals.native_session import trusted_binary_identity, trusted_supervised_binary_identity
    binary_guard = trusted_supervised_binary_identity if supervised else trusted_binary_identity
    if data['binary_identity'] != list(binary_guard(binary)):
        raise ValueError('native installation identity changed')
    policy = json_object(read_protected_artifact(root / 'native-policy.json', fixture, data['policy_sha256']))
    client = policy.get('client_id')
    if _uuid(client) != client or policy != _policy(invocation, binary, disabled_servers, client, instruction_sources, bindings) or \
            data['session']['instruction_sources'] != policy['instruction_sources'] or data['process_tree_cleanup_verified'] is not False:
        raise ValueError('native policy differs from invocation')
    command = build_session_command(invocation.execution_root, binary=binary, disabled_servers=disabled_servers,
                                    writable=invocation.kind == 'worker', invocation=invocation)
    expected = json.dumps(list(command)).encode()
    if invocation.command_sha256 != _sha(expected):
        raise ValueError('native command differs from invocation')
    if supervised:
        lifecycle = json_object(read_protected_artifact(root / 'supervisor.json', fixture,
                                                       data.get('supervisor_receipt_sha256')))
        verify_lifecycle(lifecycle, _lifecycle_bindings(invocation, data), returncode=data['returncode'])
    elif data.get('supervisor_receipt_sha256') is not None:
        raise ValueError('direct invocation cannot carry a supervisor receipt')
    request = json_object(read_protected_artifact(root / 'rpc.out.jsonl', fixture, data['rpc_out_sha256']))
    expected_request = {'id': REQUEST_ID, 'method': 'turn/start', 'params': {'threadId': invocation.session_id,
        'clientUserMessageId': client, 'input': [{'type': 'text', 'text': canonical_prompt(invocation, bindings), 'text_elements': []}]}}
    if request != expected_request or data['returncode'] != 0:
        raise ValueError('native request or exit differs from invocation')
    dispatch = _Dispatch(invocation.session_id, invocation.execution_root, canonical_prompt(invocation, bindings), client,
                         invocation)
    finish_callbacks = _replay_callbacks(invocation, data, dispatch)
    raw = read_protected_artifact(root / 'rpc.in.jsonl', fixture, data['rpc_in_sha256'])
    if not raw.endswith('\n'):
        raise ValueError('incomplete native transport line')
    for line in raw.splitlines():
        message = json_object(line)
        if message.get('method') in ACCOUNTS:
            raise ValueError('unexpected private account payload in turn artifact')
        if 'method' in message:
            dispatch.notification(message)
        else:
            dispatch.response(message)
    turn = dispatch.collector.result()
    if data['turn_sha256'] != _sha(_json(asdict(turn))):
        raise ValueError('native turn projection changed')
    return _receipt(invocation, turn, data, finish_callbacks())


def load_native_turn(invocation: Invocation, *, binary: BinaryPin,
                     disabled_servers: tuple[str, ...] = (),
                     instruction_sources: tuple[tuple[str, str], ...] = ()) -> NativeReceipt:
    if invocation.kind != 'worker':
        raise ValueError('worker loading cannot consume review evidence')
    receipt = _read_native_turn(invocation, binary=binary, disabled_servers=disabled_servers,
                               instruction_sources=instruction_sources)
    consume_invocation(invocation.fixture, invocation)
    return receipt
