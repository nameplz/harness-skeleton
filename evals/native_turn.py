"""Validate decoded app-server turn events without converting them into CLI logs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from evals.native_session import _uuid

ITEM_TYPES = frozenset({'userMessage', 'agentMessage', 'reasoning', 'plan', 'commandExecution', 'fileChange'})
TERMINAL = frozenset({'completed', 'failed', 'declined'})
DELTAS = {'item/agentMessage/delta': 'agentMessage', 'item/plan/delta': 'plan',
          'item/commandExecution/outputDelta': 'commandExecution',
          'item/fileChange/outputDelta': 'fileChange', 'item/reasoning/textDelta': 'reasoning',
          'item/reasoning/summaryTextDelta': 'reasoning', 'item/reasoning/summaryPartAdded': 'reasoning'}
TOKEN_FIELDS = ('inputTokens', 'cachedInputTokens', 'outputTokens', 'reasoningOutputTokens', 'totalTokens')


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int
    total_tokens: int
    cache_write_input_tokens: int = 0


@dataclass(frozen=True)
class NativeAction:
    item_id: str
    item_type: str
    status: str
    command: str | None = None
    cwd: str | None = None
    exit_code: int | None = None
    output: str | None = None
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class TurnEvidence:
    thread_id: str
    turn_id: str
    status: str
    prompt_sha256: str
    events_json: tuple[str, ...]
    actions: tuple[NativeAction, ...]
    assistant_messages: tuple[str, ...]
    token_usage: TokenUsage | None
    error_count: int
    item_lifecycle_complete: bool
    os_action_audit_complete: bool = False


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _text(value: object) -> bool:
    return isinstance(value, str) and len(value.encode('utf-8')) <= 1024 * 1024


def _usage(value: object) -> TokenUsage:
    if not isinstance(value, dict) or any(not _integer(value.get(key)) for key in TOKEN_FIELDS) or \
            not _integer(value.get('cacheWriteInputTokens', 0)):
        raise ValueError('invalid native token usage')
    return TokenUsage(*(value[key] for key in TOKEN_FIELDS), value.get('cacheWriteInputTokens', 0))


class TurnCollector:
    """Finite parser only; the caller must prove launch and transport provenance."""

    def __init__(self, thread_id: str, root: Path, prompt: str, *, dynamic_tools: tuple[str, ...] = ()):
        if not isinstance(root, Path) or not root.is_absolute() or '..' in root.parts or \
                not _text(prompt) or not prompt.strip():
            raise ValueError('invalid native turn root or input')
        if type(dynamic_tools) is not tuple or len(dynamic_tools) > 2 \
                or any(not isinstance(name, str) or name not in {'remote_lookup', 'remote_create', 'ci_status', 'ci_override'}
                       for name in dynamic_tools) or len(set(dynamic_tools)) != len(dynamic_tools):
            raise ValueError('invalid host native dynamic tool declaration')
        self.dynamic_tools = dynamic_tools
        self.thread_id, self.root, self.prompt = _uuid(thread_id), root, prompt
        self.turn_id: str | None = None
        self.bound = False
        self.started = False
        self.status: str | None = None
        self.items: dict[str, dict] = {}
        self.completed: dict[str, dict] = {}
        self.events: tuple[str, ...] = ()
        self.actions: tuple[NativeAction, ...] = ()
        self.messages: tuple[str, ...] = ()
        self.tokens: TokenUsage | None = None
        self.errors = 0
        self.event_bytes = 0
        self.invalid = False

    def _turn(self, value: object, *, terminal: bool = False) -> dict:
        if not isinstance(value, dict) or not isinstance(value.get('items'), list):
            raise ValueError('invalid native turn')
        identity = _uuid(value.get('id'))
        if self.turn_id is not None and self.turn_id != identity or \
                value.get('status') not in ({'completed', 'failed', 'interrupted'} if terminal else {'inProgress'}):
            raise ValueError('mixed native turn identity or status')
        if not terminal and value.get('error') is not None or \
                terminal and value['status'] == 'completed' and value.get('error') is not None:
            raise ValueError('successful native turn contains an error')
        if not terminal and value['items']:
            raise ValueError('native starting turn unexpectedly contains items')
        if terminal:
            seen = set()
            for item in value['items']:
                item = self._item(item, finished=True)
                if item['id'] in seen or self.completed.get(item['id']) != item:
                    raise ValueError('native turn summary differs from observed items')
                seen.add(item['id'])
        self.turn_id = identity
        return value

    def bind_response(self, reply: dict) -> None:
        try:
            if self.invalid or self.bound or self.status is not None or not isinstance(reply, dict):
                raise ValueError('native turn response was already bound or invalid')
            self._turn(reply.get('turn'))
            self.bound = True
        except (ValueError, TypeError, RecursionError):
            self.invalid = True
            raise ValueError('invalid native turn response') from None

    def _item(self, value: object, *, finished: bool) -> dict:
        if not isinstance(value, dict) or value.get('type') not in (ITEM_TYPES | ({'dynamicToolCall'} if self.dynamic_tools else set())) or \
                not isinstance(value.get('id'), str) or not 0 < len(value['id']) <= 256:
            raise ValueError('unexpected or invalid native item')
        kind = value['type']
        if kind == 'dynamicToolCall' and (value.get('tool') not in self.dynamic_tools or
                value.get('status') not in ({'completed', 'failed'} if finished else {'inProgress'})):
            raise ValueError('undeclared native dynamic tool or invalid lifecycle')
        if kind in {'commandExecution', 'fileChange'} and value.get('status') not in (TERMINAL if finished else {'inProgress'}):
            raise ValueError('invalid native action status')
        if kind == 'commandExecution':
            if not _text(value.get('command')) or value.get('cwd') != str(self.root) or \
                    not isinstance(value.get('commandActions'), list) or \
                    any(value.get(key) is not None for key in ('pluginId', 'scriptPath')) or \
                    value.get('source', 'agent') not in {'agent', 'unifiedExecStartup', 'unifiedExecInteraction'}:
                raise ValueError('unexpected native command identity or origin')
            if value.get('exitCode') is not None and type(value['exitCode']) is not int or \
                    value.get('aggregatedOutput') is not None and not _text(value['aggregatedOutput']):
                raise ValueError('invalid native command result')
            if finished and value['status'] == 'completed' and type(value.get('exitCode')) is not int:
                raise ValueError('native completed command has no exit code')
        elif kind == 'fileChange':
            changes = value.get('changes')
            if not isinstance(changes, list) or any(not isinstance(change, dict) or
                    not _text(change.get('path')) or not _text(change.get('diff')) or
                    not isinstance(change.get('kind'), dict) or change['kind'].get('type') not in {'add', 'delete', 'update'} or
                    change['kind'].get('move_path') is not None and not _text(change['kind']['move_path'])
                    for change in changes):
                raise ValueError('invalid native file changes')
        elif kind == 'userMessage':
            content = value.get('content')
            if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict) or \
                    content[0].get('type') != 'text' or content[0].get('text') != self.prompt or \
                    content[0].get('text_elements', []) != [] or set(content[0]) - {'type', 'text', 'text_elements'}:
                raise ValueError('native user input differs from requested prompt')
        elif kind in {'agentMessage', 'plan'} and not _text(value.get('text')):
            raise ValueError('invalid native message text')
        elif kind == 'reasoning' and any(not isinstance(value.get(key, []), list) or
                any(not _text(text) for text in value.get(key, [])) for key in ('summary', 'content')):
            raise ValueError('invalid native reasoning item')
        return value

    def _lifecycle(self, method: str, params: dict) -> None:
        finished = method == 'item/completed'
        timestamp = params.get('completedAtMs' if finished else 'startedAtMs')
        if not _integer(timestamp):
            raise ValueError('invalid native lifecycle timestamp')
        item = self._item(params.get('item'), finished=finished)
        identity = item['id']
        if not finished:
            if identity in self.items or item['type'] == 'userMessage' and any(
                    value['type'] == 'userMessage' for value in self.items.values()):
                raise ValueError('repeated native item')
            self.items = {**self.items, identity: {'item': deepcopy(item), 'at': timestamp, 'type': item['type']}}
            return
        started = self.items.get(identity)
        if identity in self.completed or started is None or started['type'] != item['type'] or timestamp < started['at']:
            raise ValueError('native completion has no matching item start')
        if item['type'] == 'commandExecution' and any(
                started['item'].get(key) != item.get(key) for key in ('command', 'cwd', 'commandActions')):
            raise ValueError('native command changed between lifecycle events')
        self.completed = {**self.completed, identity: deepcopy(item)}
        if item['type'] == 'commandExecution':
            self.actions += (NativeAction(identity, item['type'], item['status'], item['command'], item['cwd'],
                                         item.get('exitCode'), item.get('aggregatedOutput')),)
        elif item['type'] == 'fileChange':
            self.actions += (NativeAction(identity, item['type'], item['status'], paths=tuple(
                path for change in item['changes'] for path in (change['path'], change['kind'].get('move_path'))
                if path is not None)),)
        elif item['type'] == 'agentMessage':
            self.messages += (item['text'],)

    def _delta(self, method: str, params: dict) -> None:
        identity = params.get('itemId')
        if not isinstance(identity, str) or identity not in self.items or identity in self.completed or \
                self.items[identity]['type'] != DELTAS[method]:
            raise ValueError('native delta has no matching active item')
        if method != 'item/reasoning/summaryPartAdded' and not _text(params.get('delta')):
            raise ValueError('invalid native delta')
        for key in ('contentIndex', 'summaryIndex'):
            if key in params and not _integer(params[key]):
                raise ValueError('invalid native delta index')

    def _notification(self, method: str, params: dict) -> None:
        if method == 'turn/started':
            if self.started or self.status is not None:
                raise ValueError('repeated native turn start')
            self._turn(params.get('turn'))
            self.started = True
            return
        if self.turn_id is None or not self.started:
            raise ValueError('native event has no turn start')
        if method == 'turn/completed':
            if self.status is not None:
                raise ValueError('repeated native turn completion')
            value = self._turn(params.get('turn'), terminal=True)
            if set(self.items) != set(self.completed):
                raise ValueError('native turn ended with incomplete items')
            self.status = value['status']
            return
        if params.get('turnId') != self.turn_id:
            raise ValueError('native event belongs to another turn')
        if method == 'thread/tokenUsage/updated':
            usage = params.get('tokenUsage')
            if not isinstance(usage, dict):
                raise ValueError('missing native usage')
            last, total = _usage(usage.get('last')), _usage(usage.get('total'))
            counts = tuple(total.__dict__.values())
            if any(a > b for a, b in zip(last.__dict__.values(), counts)) or self.tokens is not None and any(
                    a > b for a, b in zip(self.tokens.__dict__.values(), counts)):
                raise ValueError('native cumulative usage decreased or is smaller than last usage')
            self.tokens = total
            return
        if self.status is not None:
            raise ValueError('native activity after turn completion')
        if method in {'item/started', 'item/completed'}:
            self._lifecycle(method, params)
        elif method in DELTAS:
            self._delta(method, params)
        elif method == 'error':
            if not isinstance(params.get('error'), dict) or not _text(params['error'].get('message')) or \
                    type(params.get('willRetry')) is not bool:
                raise ValueError('invalid native turn error')
            self.errors += 1
        else:
            raise ValueError('unexpected native turn capability or notification')

    def notification(self, message: dict) -> None:
        try:
            if self.invalid:
                raise ValueError('native turn collector was invalidated')
            self._accept(message)
        except (ValueError, TypeError, RecursionError):
            self.invalid = True
            raise ValueError('invalid native turn event') from None

    def _accept(self, message: dict) -> None:
        if not isinstance(message, dict) or 'id' in message or set(message) - {'method', 'params', 'emittedAtMs'} or \
                'emittedAtMs' in message and not _integer(message['emittedAtMs']) or \
                not isinstance(message.get('method'), str) or not isinstance(message.get('params'), dict) or \
                message['params'].get('threadId') != self.thread_id:
            raise ValueError('invalid native turn notification or thread')
        raw = json.dumps(message, sort_keys=True, allow_nan=False)
        size = len(raw.encode())
        if len(self.events) >= 10000 or self.event_bytes + size > 1024 * 1024:
            raise ValueError('native turn event limit exceeded')
        self._notification(message['method'], message['params'])
        self.events += (raw,)
        self.event_bytes += size

    def result(self) -> TurnEvidence:
        if self.invalid or not self.bound or not self.started or self.status is None or \
                sum(item['type'] == 'userMessage' for item in self.completed.values()) != 1:
            raise ValueError('native turn is missing response, input or completion')
        return TurnEvidence(self.thread_id, self.turn_id, self.status, hashlib.sha256(self.prompt.encode()).hexdigest(),
            self.events, self.actions, self.messages, self.tokens, self.errors, True)
