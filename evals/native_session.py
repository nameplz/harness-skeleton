"""Inspect one local native thread before using its execution capabilities."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
from typing import Iterator
from uuid import UUID

from evals.native_config import (BinaryPin, ConfigProjection, ConfigWarning, FEATURES,
                                InspectionFailure, _ConfigExchange, _cleanup, _sha,
                                build_config_command, project_config, trusted_binary_identity, verify_binary)
from evals.native_runtime import PROFILE, runtime_readable_roots, sandbox_options, tool_environment
from evals.runtime_trace import open_no_symlink
from scripts.command_runner import _command_environment

AUTH_MODES = frozenset({'apikey', 'chatgpt', 'chatgptAuthTokens', 'headers', 'agentIdentity',
                       'personalAccessToken', 'bedrockApiKey', 'bedrockAccessKeys'})
PLAN_TYPES = frozenset({'free', 'go', 'plus', 'pro', 'prolite', 'promax', 'team',
    'self_serve_business_prolite', 'self_serve_business_usage_based', 'business', 'ent26',
    'enterprise_cbp_automation', 'enterprise_cbp_usage_based', 'enterprise',
    'edu', 'edu_plus', 'edu_pro', 'unknown'})


class NativeSessionError(ValueError):
    def __init__(self, failure: InspectionFailure):
        self.failure = failure
        super().__init__('native session failed: ' + failure.failure_stage + '/' + failure.reason)


@dataclass(frozen=True)
class McpStatus:
    name: str
    runtime_status: str
    auth_status: str
    plugin_id_present: bool
    http_origin_present: bool


@dataclass(frozen=True)
class SessionEvidence:
    thread_id: str
    session_id: str
    model: str
    writable: bool
    profile_id: str
    profile_extends: str
    cwd_sha256: str
    workspace_roots_sha256: str
    environment_ids: tuple[str, ...]
    instruction_sources: tuple[tuple[str, str], ...]
    config: ConfigProjection
    mcp: tuple[McpStatus, ...]


@dataclass(frozen=True)
class SessionInspection:
    session: SessionEvidence
    binary_sha256: str
    command_sha256: str
    environment_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    auth_modes: tuple[str, ...]
    notification_methods: tuple[str, ...]
    warnings: tuple[ConfigWarning, ...]
    returncode: int


def build_session_command(root: Path, *, binary: BinaryPin, disabled_servers: tuple[str, ...],
                          writable: bool, invocation=None) -> tuple[str, ...]:
    if type(writable) is not bool:
        raise ValueError('native session access must be a boolean')
    base = build_config_command(root, binary=binary, disabled_servers=disabled_servers)
    environment = tool_environment(root.resolve())
    if invocation is not None:
        from evals.runtime_invocation import verify_invocation
        verify_invocation(invocation.fixture, invocation)
        if root.resolve() != invocation.execution_root or writable != (invocation.kind == 'worker'):
            raise ValueError('native command differs from its invocation')
        environment = {**environment, 'HARNESS_EVAL_NONCE': invocation.nonce,
                       'HARNESS_EVAL_INVOCATION_SHA256': invocation.sha256}
    values = '{' + ','.join(json.dumps(key) + '=' + json.dumps(value) for key, value in environment.items()) + '}'
    from evals.runtime_boundary import require_read_grants, fixture_protection
    readable = runtime_readable_roots()
    require_read_grants(fixture_protection(invocation.fixture) if invocation is not None else None, readable)
    return (*base[:-3], *sandbox_options(writable=writable, readable_roots=readable),
            '-c', 'approval_policy="never"', '-c', 'web_search="disabled"',
            '-c', 'model_reasoning_effort="high"', '-c', 'shell_environment_policy.set=' + values,
            *base[-3:])


def _uuid(value: object) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('invalid native thread identity')
    return value


def _instructions(values: object, root: Path) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError('native instruction sources unavailable')
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError('invalid native instruction source')
        path = Path(value)
        if not path.is_absolute() or path.is_relative_to(root) or path.resolve().is_relative_to(root) or \
                path.name not in {'AGENTS.md', 'AGENTS.override.md'}:
            raise ValueError('candidate or unknown native instructions were loaded')
        with os.fdopen(open_no_symlink(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                raise ValueError('native instructions are not bounded and regular')
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError('native instructions exceeded their byte limit')
        result.append((_sha(value), hashlib.sha256(content).hexdigest()))
    return tuple(result)


def _thread(reply: dict, root: Path, model: str, writable: bool) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    thread = reply.get('thread')
    parent = ':workspace' if writable else ':read-only'
    expected_environment = [{'environmentId': 'local', 'cwd': str(root), 'runtimeWorkspaceRoots': [str(root)]}]
    if not isinstance(thread, dict) or thread.get('ephemeral') is not True or \
            thread.get('environments') != expected_environment or reply.get('runtimeWorkspaceRoots') != [str(root)] or \
            reply.get('cwd') != str(root) or reply.get('model') != model or \
            reply.get('activePermissionProfile') != {'id': PROFILE, 'extends': parent} or \
            reply.get('approvalPolicy') != 'never' or reply.get('approvalsReviewer') != 'user':
        raise ValueError('native thread differs from its requested local profile')
    sandbox = reply.get('sandbox')
    sandbox_fields = {'type', 'networkAccess'} | ({'writableRoots', 'excludeTmpdirEnvVar', 'excludeSlashTmp'} if writable else set())
    if not isinstance(sandbox, dict) or sandbox.get('type') != ('workspaceWrite' if writable else 'readOnly') or \
            set(sandbox) != sandbox_fields or sandbox.get('networkAccess') is not False:
        raise ValueError('native sandbox projection differs from its requested profile')
    if writable and (sandbox.get('writableRoots') not in ([], [str(root)]) or
                     sandbox.get('excludeTmpdirEnvVar') is not True or sandbox.get('excludeSlashTmp') is not True):
        raise ValueError('native sandbox projection has unexpected writable roots')
    thread_id, session_id = _uuid(thread.get('id')), _uuid(thread.get('sessionId'))
    if thread_id != session_id:
        raise ValueError('native session is not a fresh thread')
    return thread_id, session_id, _instructions(reply.get('instructionSources'), root)


def _mcp(reply: dict, name: str) -> McpStatus:
    data = reply.get('data')
    if not isinstance(data, list) or len(data) != 1 or reply.get('nextCursor') is not None:
        raise ValueError('native named MCP inventory unavailable')
    value = data[0]
    if not isinstance(value, dict) or value.get('name') != name or value.get('runtimeStatus') != 'disabled' or \
            value.get('authStatus') != 'unsupported' or value.get('tools') != {} or \
            value.get('resources') != [] or value.get('resourceTemplates') != [] or \
            any(value.get(key) is not None for key in ('toolsError', 'serverInfo', 'serverCapabilities')):
        raise ValueError('native MCP capability is active, missing or invalid')
    return McpStatus(name, 'disabled', 'unsupported', value.get('pluginId') is not None, value.get('httpOrigin') is not None)


def _config_matches(config: ConfigProjection, disabled_servers: tuple[str, ...]) -> bool:
    if not config.catalog_reported or config.servers != tuple(sorted((name, False) for name in disabled_servers)) or \
            config.features != tuple((name, False) for name in FEATURES) or not config.layers or not config.origins:
        return False
    origins = dict(config.origins)
    settings = [*(f'features.{name}' for name in FEATURES if name != 'code_mode'),
                *(f'mcp_servers.{name}.enabled' for name in disabled_servers)]
    return any(layer.source.source_type == 'sessionFlags' for layer in config.layers) and all(
        name in origins and origins[name].source_type == 'sessionFlags' for name in settings)


class _SessionExchange(_ConfigExchange):
    def __init__(self, process: subprocess.Popen[bytes], deadline: float, limit: int,
                 command: tuple[str, ...], environment: dict[str, str]):
        super().__init__(process, deadline, limit)
        self.command_sha256 = hashlib.sha256(json.dumps(command).encode()).hexdigest()
        self.environment_sha256 = hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
        self.auth_modes: set[str] = set()
        self.started: list[str] = []
        self.closed: list[str] = []
        self.thread_id: str | None = None
        self.invocation = None
        self.turn_handler = None
        self.raw_handler = None

    def decode(self, raw: bytes) -> dict:
        message = super().decode(raw)
        if self.raw_handler is not None:
            self.raw_handler(raw, message)
        return message

    def notification(self, message: dict) -> None:
        if self.turn_handler is not None:
            self.turn_handler(message)
            return
        method, params = message.get('method'), message.get('params')
        if 'id' in message:
            raise ValueError('unexpected native server request')
        if method == 'account/updated':
            if not isinstance(params, dict) or set(params) - {'authMode', 'planType'} or \
                    params.get('authMode') is not None and params.get('authMode') not in AUTH_MODES or \
                    params.get('planType') is not None and params.get('planType') not in PLAN_TYPES:
                raise ValueError('invalid native account notification')
            if params.get('authMode') is not None:
                self.auth_modes.add(params['authMode'])
        elif method == 'thread/started':
            thread = params.get('thread') if isinstance(params, dict) else None
            if not isinstance(thread, dict):
                raise ValueError('invalid native thread notification')
            identity = _uuid(thread.get('id'))
            if self.started or self.thread_id is not None and identity != self.thread_id or \
                    'sessionId' in thread and thread['sessionId'] != identity:
                raise ValueError('mixed or repeated native thread notification')
            self.started.append(identity)
        elif method == 'thread/closed' and self.stage == 'shutdown':
            if not isinstance(params, dict) or params.get('threadId') != self.thread_id or self.closed:
                raise ValueError('mixed or repeated native thread closure')
            self.closed.append(self.thread_id)
        else:
            super().notification(message)
            if any(warning.category != 'project_configuration_disabled' for warning in self.warnings):
                raise ValueError('unclassified native configuration warning')
        self.notifications.add(method)

    def preflight(self, root: Path, model: str, writable: bool, disabled_servers: tuple[str, ...],
                  developer_instructions: str = '') -> SessionEvidence:
        self.request(1, 'initialize', {'clientInfo': {'name': 'harness-native-session', 'version': '1'},
            'capabilities': {'experimentalApi': True, 'requestAttestation': False, 'extensions': {},
                            'explicitGatewayOauth': True, 'mcpServerOpenaiFormElicitation': False}})
        self.send({'method': 'initialized'})
        self.stage = 'config/read'
        config = project_config(self.request(2, 'config/read', {'cwd': str(root), 'includeLayers': True}))
        if not _config_matches(config, disabled_servers):
            raise ValueError('native configuration does not match the finite capability policy')
        self.stage = 'configRequirements/read'
        requirements = self.request(3, 'configRequirements/read', {})
        if 'requirements' not in requirements or requirements['requirements'] is not None:
            raise ValueError('native managed requirements need separate interpretation')
        self.stage = 'permissionProfile/list'
        reply = self.request(4, 'permissionProfile/list', {'cwd': str(root), 'cursor': None, 'limit': None})
        profiles = reply.get('data')
        selected = [value for value in profiles if isinstance(value, dict) and value.get('id') == PROFILE] if isinstance(profiles, list) else []
        if len(selected) != 1 or selected[0].get('allowed') is not True or reply.get('nextCursor') is not None:
            raise ValueError('native permission profile is missing or disallowed')
        self.stage = 'thread/start'
        reply = self.request(5, 'thread/start', {'model': model, 'cwd': str(root), 'runtimeWorkspaceRoots': [str(root)],
            'permissions': PROFILE, 'approvalPolicy': 'never', 'approvalsReviewer': 'user', 'developerInstructions': developer_instructions,
            'dynamicTools': [], 'selectedCapabilityRoots': [],
            'environments': [{'environmentId': 'local', 'cwd': str(root), 'runtimeWorkspaceRoots': [str(root)]}],
            'ephemeral': True, 'experimentalRawEvents': False, 'allowProviderModelFallback': False})
        identity, session_id, sources = _thread(reply, root, model, writable)
        self.thread_id = identity
        if self.started and self.started != [identity]:
            raise ValueError('native thread notification disagrees with response')
        statuses = []
        for request_id, name in enumerate(disabled_servers, 6):
            self.stage = 'mcpServerStatus/list'
            statuses.append(_mcp(self.request(request_id, 'mcpServerStatus/list', {
                'threadId': identity, 'serverName': name, 'detail': 'full', 'cursor': None, 'limit': 1}), name))
        return SessionEvidence(identity, session_id, model, writable, PROFILE, ':workspace' if writable else ':read-only',
            _sha(str(root)), _sha([str(root)]), ('local',), sources, config, tuple(statuses))


@contextmanager
def native_session(root: Path, *, binary: BinaryPin, model: str, writable: bool = False,
                   disabled_servers: tuple[str, ...] = (), timeout_seconds: float = 30,
                   max_output_bytes: int = 1024 * 1024, invocation=None,
                   developer_instructions: str = '') -> Iterator[tuple[_SessionExchange, SessionEvidence]]:
    """Trusted host context: retain the gated process for a subsequent bound collector."""
    if os.name != 'posix' or not isinstance(model, str) or not model.strip() or len(model) > 128 or \
            type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 300 or \
            type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 1024 * 1024 or \
            not isinstance(developer_instructions, str) or len(developer_instructions.encode()) > 32768:
        raise ValueError('invalid native session limits or model')
    verify_binary(binary)
    binary_identity = trusted_binary_identity(binary) if invocation is not None else None
    root = root.resolve(strict=True)
    command = build_session_command(root, binary=binary, disabled_servers=disabled_servers,
                                    writable=writable, invocation=invocation)
    if invocation is not None:
        from evals.runtime_invocation import bind_session, claim_native_launch
        if model != invocation.model:
            raise ValueError('native model differs from its invocation')
        invocation = claim_native_launch(invocation, command, binary=binary, disabled_servers=disabled_servers)
    environment = _command_environment()
    deadline = time.monotonic() + timeout_seconds
    if binary_identity is not None and trusted_binary_identity(binary) != binary_identity:
        raise ValueError('native installation changed before process creation')
    try:
        process = subprocess.Popen(command, cwd=root, env=environment, shell=False, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
    except OSError as error:
        raise NativeSessionError(InspectionFailure('spawn', 'spawn_error', type(error).__name__, error.errno, None, None, None)) from None
    exchange, original = None, None
    try:
        exchange = _SessionExchange(process, deadline, max_output_bytes, command, environment)
        exchange.binary_identity = binary_identity
        evidence = exchange.preflight(root, model, writable, disabled_servers, developer_instructions)
        exchange.invocation = bind_session(invocation, evidence.session_id) if invocation is not None else None
        yield exchange, evidence
        exchange.stage = 'shutdown'
        exchange.finish()
        if exchange.started != [evidence.thread_id]:
            raise ValueError('native thread start notification unavailable')
        exchange.stage = 'binary recheck'
        verify_binary(binary)
    except Exception as error:
        original = error
    finally:
        cleanup = _cleanup(process, exchange)
    if original is not None or cleanup is not None:
        reason = {'native inspection timed out': 'timeout', 'native inspection output limit exceeded': 'output_limit'}.get(
            str(original), 'exchange_error' if original else 'cleanup_error')
        raise NativeSessionError(InspectionFailure(exchange.stage if exchange and original else 'cleanup', reason,
            type(original).__name__ if original else None, getattr(original, 'errno', None),
            type(cleanup).__name__ if cleanup else None, getattr(cleanup, 'errno', None), process.poll())) from None


def inspect_native_session(root: Path, *, binary: BinaryPin, model: str, writable: bool = False,
                           disabled_servers: tuple[str, ...] = (), timeout_seconds: float = 30,
                           max_output_bytes: int = 1024 * 1024) -> SessionInspection:
    with native_session(root, binary=binary, model=model, writable=writable, disabled_servers=disabled_servers,
                        timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes) as (exchange, evidence):
        pass
    return SessionInspection(evidence, binary.sha256, exchange.command_sha256, exchange.environment_sha256,
        *(digest.hexdigest() for digest in exchange.digests), *exchange.counts, tuple(sorted(exchange.auth_modes)),
        tuple(sorted(exchange.notifications)), tuple(exchange.warnings), exchange.process.returncode)
