"""Host-owned, one-use collection of an actual same-process native turn."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import re
from pathlib import Path
from uuid import uuid4

from evals.native_config import BinaryPin, verify_binary
from evals.native_review import ReviewBindings, canonical_prompt, verify_review_snapshot
from evals.native_session import _uuid, build_session_command, native_session
from evals.native_telemetry import validate_account
from evals.native_turn import DELTAS, TurnCollector, TurnEvidence, _integer
from evals.runtime_invocation import Invocation, consume_invocation, verify_invocation
from evals.runtime_trace import json_object, read_host_artifact, read_protected_artifact
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
    return {'schema': 1, 'invocation_sha256': invocation.sha256, 'source_sha256': invocation.source.source_sha256,
            'binary_sha256': binary.sha256, 'disabled_servers': list(servers), 'request_id': REQUEST_ID,
            'client_id': client, 'prompt_sha256': _sha(canonical_prompt(invocation, bindings).encode()),
            'review_bindings': bindings.as_dict() if bindings is not None else None,
            'instruction_sources': [list(row) for row in instructions],
            'environment_sha256': _sha(json.dumps(_command_environment(), sort_keys=True).encode()),
            'guidance_sha256': _sha(native_guidance(invocation).encode())}


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


class _Dispatch:
    def __init__(self, thread: str, root: Path, prompt: str, client: str):
        self.collector = TurnCollector(thread, root, prompt)
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
        self.collector.notification(message)

    def response(self, message: dict) -> None:
        if set(message) != {'id', 'result'} or type(message['id']) is not int or message['id'] != REQUEST_ID:
            raise ValueError('native response differs from request identity')
        self.collector.bind_response(message['result'])
        for event in self.pending:
            self._turn_event(event)
        self.pending = ()


def _pop(exchange) -> dict:
    while b'\n' not in exchange.buffer:
        exchange.pump()
    raw, _, tail = exchange.buffer.partition(b'\n')
    exchange.buffer = bytearray(tail)
    return exchange.decode(bytes(raw))


def collect_native_turn(invocation: Invocation, *, binary: BinaryPin,
                        disabled_servers: tuple[str, ...] = (), timeout_seconds: float = 300,
                        max_output_bytes: int = 1024 * 1024,
                        instruction_sources: tuple[tuple[str, str], ...] = (),
                        review_bindings: ReviewBindings | None = None) -> NativeReceipt:
    verify_invocation(invocation.fixture, invocation)
    bindings = review_bindings
    canonical_prompt(invocation, bindings)
    if invocation.kind != 'worker':
        verify_review_snapshot(invocation, bindings)
    client = str(uuid4())
    policy = _json(_policy(invocation, binary, disabled_servers, client, instruction_sources, bindings))
    root = invocation.artifact_root
    try:
        with (root / 'native-policy.json').open('xb') as stream:
            stream.write(policy)
    except FileExistsError:
        raise ValueError('native invocation was already attempted') from None
    request = {'id': REQUEST_ID, 'method': 'turn/start', 'params': {
        'threadId': None, 'clientUserMessageId': client,
        'input': [{'type': 'text', 'text': canonical_prompt(invocation, bindings), 'text_elements': []}]}}
    with (root / 'rpc.in.jsonl').open('xb') as incoming:
        with native_session(invocation.execution_root, binary=binary, model=invocation.model,
                writable=invocation.kind == 'worker', disabled_servers=disabled_servers, timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes, invocation=invocation,
                developer_instructions=native_guidance(invocation)) as (exchange, session):
            if session.instruction_sources != instruction_sources:
                raise ValueError('native instructions differ from host-approved sources')
            dispatch = _run_turn(exchange, session.thread_id, invocation, client, request, incoming, bindings)
        turn = dispatch.collector.result()  # Includes notifications drained during shutdown.
    verify_invocation(invocation.fixture, exchange.invocation, require_session=True)
    if invocation.kind != 'worker':
        verify_review_snapshot(exchange.invocation, bindings)
    return _seal(exchange, session, dispatch, turn, policy)


def _run_turn(exchange, thread_id: str, invocation: Invocation, client: str, request: dict, incoming, bindings: ReviewBindings | None) -> _Dispatch:
    root = invocation.artifact_root
    dispatch = _Dispatch(thread_id, invocation.execution_root, canonical_prompt(invocation, bindings), client)
    def capture(raw: bytes, message: dict) -> None:
        # Account/config payloads stay private. This file is a filtered turn transport log.
        if 'method' not in message or message.get('method') in TURN_METHODS | BOOKKEEPING:
            incoming.write(raw + b'\n')
            incoming.flush()
    exchange.raw_handler, exchange.turn_handler = capture, dispatch.notification
    exchange.stage = 'turn/run'
    request = {**request, 'params': {**request['params'], 'threadId': thread_id}}
    request_raw = (json.dumps(request) + '\n').encode()
    if len(request_raw) > 65536:
        raise ValueError('native turn request exceeded its byte limit')
    with (root / 'rpc.out.jsonl').open('xb') as outgoing:
        outgoing.write(request_raw)
    exchange.send(request)
    while not dispatch.collector.bound or dispatch.collector.status is None:
        message = _pop(exchange)
        if 'method' in message:
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
    raw = _json(metadata)
    with (root / 'turn.json').open('xb') as stream:
        stream.write(raw)
    bound = replace(exchange.invocation, native_receipt_sha256=_sha(raw))
    return _receipt(bound, turn, metadata)


def _receipt(invocation: Invocation, turn: TurnEvidence, data: dict) -> NativeReceipt:
    return NativeReceipt(invocation, turn, data['rpc_in_sha256'], data['rpc_out_sha256'], data['policy_sha256'],
        data['stdout_sha256'], data['stderr_sha256'], data['stdout_bytes'], data['stderr_bytes'],
        data['environment_sha256'], json.dumps(data['session'], sort_keys=True),
        tuple(tuple(row) for row in data['telemetry']), data['returncode'], data['process_tree_cleanup_verified'])


def _read_native_turn(invocation: Invocation, *, binary: BinaryPin,
                     disabled_servers: tuple[str, ...] = (),
                     instruction_sources: tuple[tuple[str, str], ...] = (),
                     review_bindings: ReviewBindings | None = None) -> NativeReceipt:
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
    from evals.native_session import trusted_binary_identity
    if data['binary_identity'] != list(trusted_binary_identity(binary)):
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
    request = json_object(read_protected_artifact(root / 'rpc.out.jsonl', fixture, data['rpc_out_sha256']))
    expected_request = {'id': REQUEST_ID, 'method': 'turn/start', 'params': {'threadId': invocation.session_id,
        'clientUserMessageId': client, 'input': [{'type': 'text', 'text': canonical_prompt(invocation, bindings), 'text_elements': []}]}}
    if request != expected_request or data['returncode'] != 0:
        raise ValueError('native request or exit differs from invocation')
    dispatch = _Dispatch(invocation.session_id, invocation.execution_root, canonical_prompt(invocation, bindings), client)
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
    return _receipt(invocation, turn, data)


def load_native_turn(invocation: Invocation, *, binary: BinaryPin,
                     disabled_servers: tuple[str, ...] = (),
                     instruction_sources: tuple[tuple[str, str], ...] = ()) -> NativeReceipt:
    if invocation.kind != 'worker':
        raise ValueError('worker loading cannot consume review evidence')
    receipt = _read_native_turn(invocation, binary=binary, disabled_servers=disabled_servers,
                               instruction_sources=instruction_sources)
    consume_invocation(invocation.fixture, invocation)
    return receipt
