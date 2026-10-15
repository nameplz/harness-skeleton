"""Finite native callback lifecycle; the caller must authenticate its transport."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json

from evals.runtime_remote import (MAX_BYTES, MAX_CALLS, RemoteBinding, RemoteContext,
    RemoteReceipt, RemoteSession, dispatch_remote, finish_remote, start_remote, _text_id)

MAX_EVIDENCE_BYTES = 1024 * 1024


def _wire(value: object, *, max_bytes: int = MAX_BYTES) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
    except (TypeError, UnicodeError, RecursionError) as error:
        raise ValueError('invalid native dynamic JSON') from error
    if len(raw) > max_bytes:
        raise ValueError('native dynamic packet exceeds its byte limit')
    return raw


def _parse(raw: bytes) -> dict:
    from evals.runtime_trace import json_object
    if type(raw) is not bytes or len(raw) > MAX_BYTES or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('native dynamic transport must be one bounded complete line')
    try:
        value = json_object(raw.decode())
        _wire(value)  # Reject NaN/Infinity, invalid Unicode and non-data values.
        return value
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid native dynamic transport JSON') from error


@dataclass(frozen=True)
class DynamicSession:
    context: RemoteContext
    binding: RemoteBinding
    remote: RemoteSession
    transcript: tuple[str, ...] = ()
    phase: str = 'idle'
    active_json: str | None = None
    expected_response: bytes | None = None
    requests: tuple[str, ...] = ()
    responses: tuple[str, ...] = ()
    items: tuple[str, ...] = ()


@dataclass(frozen=True)
class DynamicEvidence:
    transcript: tuple[str, ...]
    requests: tuple[str, ...]
    responses: tuple[str, ...]
    items: tuple[str, ...]
    remote_receipt: RemoteReceipt
    declaration_sha256: str

    @property
    def sha256(self) -> str:
        # Evidence includes the transcript and several projections of the same packets.
        return hashlib.sha256(_wire(asdict(self), max_bytes=MAX_EVIDENCE_BYTES)).hexdigest()


def begin_dynamic(context: RemoteContext, binding: RemoteBinding) -> DynamicSession:
    return DynamicSession(context, binding, start_remote(context, binding))


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _item_packet(state: DynamicSession, row: dict, *, finished: bool) -> tuple[dict, int]:
    method = 'item/completed' if finished else 'item/started'
    clock = 'completedAtMs' if finished else 'startedAtMs'
    if set(row) - {'method', 'params', 'emittedAtMs'} or row.get('method') != method \
            or 'emittedAtMs' in row and not _integer(row['emittedAtMs']):
        raise ValueError('invalid native dynamic item envelope')
    params = row.get('params')
    if not isinstance(params, dict) or set(params) != {'threadId', 'turnId', 'item', clock} \
            or params['threadId'] != state.binding.thread_id or params['turnId'] != state.binding.turn_id \
            or not _integer(params[clock]):
        raise ValueError('native dynamic item belongs to another turn or timestamp')
    item = params['item']
    required = {'type', 'id', 'tool', 'arguments', 'status'}
    optional = {'namespace', 'contentItems', 'success', 'durationMs'}
    if not isinstance(item, dict) or not required <= set(item) or set(item) - required - optional \
            or item['type'] != 'dynamicToolCall' or not _text_id(item['id']) or item.get('namespace') is not None:
        raise ValueError('invalid native dynamic item shape')
    if not finished and (item['status'] != 'inProgress' or any(
            item.get(key) is not None for key in ('contentItems', 'success', 'durationMs'))):
        raise ValueError('native dynamic start already contains a result')
    if finished and (not isinstance(item['status'], str) or item['status'] not in {'completed', 'failed'} \
            or type(item.get('success')) is not bool \
            or item.get('durationMs') is not None and not _integer(item['durationMs'])):
        raise ValueError('invalid native dynamic completion result')
    return item, params[clock]


def _item_step(state: DynamicSession, row: dict, *, finished: bool) -> DynamicSession:
    item, timestamp = _item_packet(state, row, finished=finished)
    if not finished:
        if state.phase != 'idle' or len(state.items) >= MAX_CALLS or any(
                json.loads(previous)['id'] == item['id'] for previous in state.items):
            raise ValueError('native dynamic call is nested, repeated or over limit')
        # Validate declared tool/arguments before accepting its start, without executing it.
        request = {'threadId': state.binding.thread_id, 'turnId': state.binding.turn_id,
                   'callId': item['id'], 'namespace': None, 'tool': item['tool'], 'arguments': item['arguments']}
        dispatch_remote(state.remote, request)
        return replace(state, phase='started', active_json=_wire({'item': item, 'at': timestamp}).decode())
    if state.phase != 'responded' or state.active_json is None or state.expected_response is None:
        raise ValueError('native dynamic completion lacks a sent host response')
    active = json.loads(state.active_json)
    if timestamp < active['at'] or any(item.get(key) != active['item'].get(key)
            for key in ('id', 'namespace', 'tool', 'arguments')):
        raise ValueError('native dynamic identity changed between lifecycle events')
    result = _parse(state.expected_response)['result']
    if _wire({'success': item['success'], 'contentItems': item.get('contentItems')}) != _wire(result) \
            or item['status'] != ('completed' if result['success'] else 'failed'):
        raise ValueError('native dynamic result differs from the actual host response')
    return replace(state, phase='idle', active_json=None, expected_response=None,
                   items=(*state.items, _wire(item).decode()))


def _request_step(state: DynamicSession, row: dict, raw: bytes) -> DynamicSession:
    identity = row.get('id')
    rpc_id = type(identity) is int and -(2**63) <= identity < 2**63 or _text_id(identity)
    if state.phase != 'started' or state.active_json is None or set(row) != {'id', 'method', 'params'} \
            or row['method'] != 'item/tool/call' or not rpc_id:
        raise ValueError('invalid or out-of-order native dynamic server request')
    item = json.loads(state.active_json)['item']
    params = row['params']
    if not isinstance(params, dict) or params.get('callId') != item['id'] or any(
            _wire(params.get(key)) != _wire(item.get(key)) for key in ('tool', 'namespace', 'arguments')):
        raise ValueError('native dynamic request differs from its started item')
    remote, result = dispatch_remote(state.remote, params)
    response = _wire({'id': identity, 'result': result})
    return replace(state, remote=remote, phase='requested', expected_response=response,
                   requests=(*state.requests, raw.decode()))


def _step(state: DynamicSession, stage: str, raw: bytes) -> DynamicSession:
    if not isinstance(stage, str):
        raise ValueError('native dynamic transcript stage must be a string')
    row = _parse(raw)
    if stage in {'item/started', 'item/completed'}:
        updated = _item_step(state, row, finished=stage == 'item/completed')
    elif stage == 'request':
        updated = _request_step(state, row, raw)
    elif stage == 'response':
        if state.phase != 'requested' or state.expected_response != raw:
            raise ValueError('native dynamic sent response differs from its pending host response')
        updated = replace(state, phase='responded', responses=(*state.responses, raw.decode()))
    else:
        raise ValueError('unknown native dynamic transcript stage')
    entry = _wire({'stage': stage, 'raw': raw.decode()}).decode()
    transcript = (*state.transcript, entry)
    if len(transcript) > MAX_CALLS * 4 or sum(len(value.encode()) for value in transcript) > MAX_BYTES:
        raise ValueError('native dynamic transcript exceeds limits')
    return replace(updated, transcript=transcript)


def _replay(context: RemoteContext, binding: RemoteBinding, transcript: tuple[str, ...]) -> DynamicSession:
    if type(transcript) is not tuple or len(transcript) > MAX_CALLS * 4:
        raise ValueError('invalid native dynamic transcript')
    if any(not isinstance(entry, str) for entry in transcript) or sum(map(len, transcript)) > MAX_BYTES:
        raise ValueError('native dynamic transcript is not bounded JSON')
    try:
        raw_entries = tuple(entry.encode() for entry in transcript)
        if sum(map(len, raw_entries)) > MAX_BYTES:
            raise ValueError('native dynamic transcript byte limit exceeded')
    except UnicodeError as error:
        raise ValueError('invalid native dynamic transcript encoding') from error
    state = begin_dynamic(context, binding)
    for entry, raw in zip(transcript, raw_entries):
        row = _parse(raw)
        if set(row) != {'stage', 'raw'} or not isinstance(row['raw'], str):
            raise ValueError('invalid native dynamic transcript record')
        if len(row['raw']) > MAX_BYTES:
            raise ValueError('native dynamic transcript packet exceeds limits')
        try:
            state = _step(state, row['stage'], row['raw'].encode())
        except UnicodeError as error:
            raise ValueError('invalid native dynamic transcript packet encoding') from error
        if state.transcript[-1] != entry:
            raise ValueError('native dynamic transcript representation changed')
    return state


def _validated(state: DynamicSession) -> DynamicSession:
    if not isinstance(state, DynamicSession) or _replay(state.context, state.binding, state.transcript) != state:
        raise ValueError('native dynamic state differs from replay')
    return state


def dynamic_item(state: DynamicSession, message: dict) -> DynamicSession:
    state = _validated(state)
    if not isinstance(message, dict) or not isinstance(message.get('method'), str) \
            or message['method'] not in {'item/started', 'item/completed'}:
        raise ValueError('unexpected native dynamic item method')
    return _step(state, message['method'], _wire(message))


def dynamic_request(state: DynamicSession, raw: bytes) -> tuple[DynamicSession, bytes]:
    state = _step(_validated(state), 'request', raw)
    return state, state.expected_response


def dynamic_response_sent(state: DynamicSession, raw: bytes) -> DynamicSession:
    return _step(_validated(state), 'response', raw)


def finish_dynamic(state: DynamicSession) -> DynamicEvidence:
    state = _validated(state)
    if not state.items or state.phase != 'idle' or state.active_json is not None or state.expected_response is not None \
            or not len(state.items) == len(state.requests) == len(state.responses):
        raise ValueError('native dynamic lifecycle remains incomplete')
    return DynamicEvidence(state.transcript, state.requests, state.responses, state.items,
                           finish_remote(state.remote), state.context.protocol_sha256)


def replay_dynamic(context: RemoteContext, binding: RemoteBinding, transcript: tuple[str, ...], *,
                   expected: DynamicEvidence | None = None) -> DynamicEvidence:
    evidence = finish_dynamic(_replay(context, binding, transcript))
    if expected is not None and expected != evidence:
        raise ValueError('native dynamic evidence binding or projection changed')
    return evidence
