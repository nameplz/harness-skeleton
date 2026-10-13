"""Bounded, model-free app-server configuration inspection with no raw config logs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from typing import Any

from evals.runtime_trace import json_object, open_no_symlink
from scripts.command_runner import _command_environment, _terminate_process_group

FEATURES = ('apps', 'plugins', 'hooks', 'multi_agent', 'remote_plugin',
            'enable_mcp_apps', 'skill_mcp_dependency_install', 'code_mode')
SAFE_NAME = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
NOTIFICATIONS = frozenset({'remoteControl/status/changed'})


@dataclass(frozen=True)
class BinaryPin:
    path: Path
    sha256: str


def verify_binary(binary: BinaryPin) -> None:
    if not isinstance(binary, BinaryPin) or not isinstance(binary.path, Path) or \
            not isinstance(binary.sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', binary.sha256):
        raise ValueError('invalid native binary pin')
    with os.fdopen(open_no_symlink(binary.path), 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 256 * 1024 * 1024:
            raise ValueError('native binary is not bounded and regular')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != binary.sha256:
            raise ValueError('native binary digest mismatch')


@dataclass(frozen=True)
class InspectionFailure:
    failure_stage: str
    reason: str
    original_error_type: str | None
    original_errno: int | None
    cleanup_error_type: str | None
    cleanup_errno: int | None
    returncode: int | None


class ConfigInspectionError(ValueError):
    def __init__(self, failure: InspectionFailure):
        self.failure = failure
        super().__init__('native configuration inspection failed: ' + failure.failure_stage + '/' + failure.reason)


@dataclass(frozen=True)
class ConfigProjection:
    servers: tuple[tuple[str, bool], ...]
    features: tuple[tuple[str, bool | None], ...]
    catalog_reported: bool


@dataclass(frozen=True)
class ConfigInspection:
    config: ConfigProjection
    requirements_present: bool
    required_features: tuple[tuple[str, bool], ...]
    command_sha256: str
    binary_sha256: str
    environment_sha256: str
    requested_disabled_servers: tuple[str, ...]
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    notification_methods: tuple[str, ...]
    returncode: int


def project_config(reply: dict[str, Any]) -> ConfigProjection:
    config = reply.get('config')
    if not isinstance(config, dict):
        raise ValueError('native configuration is unavailable')
    servers, features = config.get('mcp_servers', {}), config.get('features', {})
    if not isinstance(servers, dict) or not isinstance(features, dict):
        raise ValueError('invalid native configuration shape')
    projected = []
    for name, settings in servers.items():
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or not isinstance(settings, dict):
            raise ValueError('invalid native server identity')
        enabled = settings.get('enabled', True)
        if type(enabled) is not bool:
            raise ValueError('invalid native server enabled state')
        projected.append((name, enabled))
    if any(key in features and type(features[key]) is not bool for key in FEATURES):
        raise ValueError('invalid native feature state')
    return ConfigProjection(tuple(sorted(projected)), tuple((key, features.get(key)) for key in FEATURES),
                            'mcp_servers' in config)


def build_config_command(root: Path, *, binary: BinaryPin,
                         disabled_servers: tuple[str, ...] = ()) -> tuple[str, ...]:
    if not isinstance(binary, BinaryPin) or not isinstance(binary.path, Path) or not binary.path.is_absolute():
        raise ValueError('invalid native binary pin')
    if not isinstance(disabled_servers, tuple) or len(disabled_servers) > 64 or any(
        not isinstance(name, str) or not SAFE_NAME.fullmatch(name) for name in disabled_servers
    ) or len(set(disabled_servers)) != len(disabled_servers):
        raise ValueError('invalid native server disable list')
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('inspection requires an existing directory')
    return (str(binary.path), '-C', str(root),
            *(value for feature in FEATURES for value in ('-c', f'features.{feature}=false')),
            *(value for name in disabled_servers for value in ('-c', f'mcp_servers.{name}.enabled=false')),
            '-c', 'apps._default.enabled=false', '-c', 'check_for_update_on_startup=false',
            '-c', 'projects={' + json.dumps(str(root)) + '={trust_level="untrusted"}}',
            'app-server', '--listen', 'stdio://')


class _ConfigExchange:
    """One fresh configuration-only process; no thread, model or MCP requests."""

    def __init__(self, process: subprocess.Popen[bytes], deadline: float, limit: int):
        self.process, self.deadline, self.limit = process, deadline, limit
        self.selector = selectors.DefaultSelector()
        self.buffer = bytearray()
        self.counts = [0, 0]
        self.digests = [hashlib.sha256(), hashlib.sha256()]
        self.notifications: set[str] = set()
        self.stage = 'initialize'
        for index, stream in enumerate((process.stdout, process.stderr)):
            if stream is None:
                raise ValueError('native inspection streams unavailable')
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, index)

    def send(self, value: dict[str, Any]) -> None:
        raw = (json.dumps(value) + '\n').encode()
        if len(raw) > 65536 or self.process.stdin is None:
            raise ValueError('invalid configuration request')
        try:
            # Only four small, fixed requests are sent; no untrusted request body is forwarded.
            self.process.stdin.write(raw)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise ValueError('native inspection input closed') from None

    def pump(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('native inspection timed out')
        if not self.selector.get_map():
            raise ValueError('native inspection ended before its response')
        for key, _ in self.selector.select(min(remaining, 0.1)):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            index = key.data
            self.counts[index] += len(chunk)
            if sum(self.counts) > self.limit:
                raise ValueError('native inspection output limit exceeded')
            self.digests[index].update(chunk)
            if index == 0:
                self.buffer.extend(chunk)

    def receive(self, request_id: int) -> dict[str, Any]:
        while True:
            if b'\n' not in self.buffer:
                self.pump()
                continue
            raw, _, tail = self.buffer.partition(b'\n')
            self.buffer = bytearray(tail)
            try:
                message = json_object(raw.decode('utf-8'))
            except (ValueError, UnicodeError):
                raise ValueError('invalid native inspection response') from None
            if 'method' in message:
                method = message['method']
                if not isinstance(method, str) or method not in NOTIFICATIONS or 'id' in message:
                    raise ValueError('unexpected native capability activity during configuration inspection')
                self.notifications.add(method)
                continue
            if type(message.get('id')) is not int or message['id'] != request_id or \
                    'error' in message or not isinstance(message.get('result'), dict):
                raise ValueError('native configuration request failed or mismatched')
            return message['result']

    def request(self, request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.send({'id': request_id, 'method': method, 'params': params})
        return self.receive(request_id)

    def configuration(self, root: Path, binary: BinaryPin, command: tuple[str, ...],
                      environment: dict[str, str], disabled_servers: tuple[str, ...]) -> ConfigInspection:
        self.request(1, 'initialize', {'clientInfo': {'name': 'harness-config-probe', 'version': '1'},
            'capabilities': {'experimentalApi': True, 'requestAttestation': False,
                             'explicitGatewayOauth': True, 'mcpServerOpenaiFormElicitation': False}})
        self.send({'method': 'initialized'})
        self.stage = 'config/read'
        config = project_config(self.request(2, 'config/read', {'cwd': str(root.resolve()), 'includeLayers': False}))
        self.stage = 'configRequirements/read'
        reply = self.request(3, 'configRequirements/read', {})
        if 'requirements' not in reply or reply['requirements'] is not None and not isinstance(reply['requirements'], dict):
            raise ValueError('native requirements unavailable')
        requirements = reply['requirements']
        features = (requirements or {}).get('featureRequirements')
        features = {} if features is None else features
        if not isinstance(features, dict) or any(not isinstance(key, str) or not SAFE_NAME.fullmatch(key) or
                                                type(value) is not bool for key, value in features.items()):
            raise ValueError('invalid native feature requirements')
        self.stage = 'shutdown'
        self.finish()
        self.stage = 'binary recheck'
        verify_binary(binary)
        return ConfigInspection(config, requirements is not None, tuple(sorted(features.items())),
            hashlib.sha256(json.dumps(command).encode()).hexdigest(), binary.sha256,
            hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest(),
            disabled_servers,
            *(digest.hexdigest() for digest in self.digests), *self.counts,
            tuple(sorted(self.notifications)), self.process.returncode)

    def finish(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        while self.selector.get_map():
            self.pump()
        if self.buffer.strip():
            raise ValueError('unexpected trailing native inspection output')
        try:
            self.process.wait(timeout=max(0.001, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ValueError('native inspection did not exit') from None
        if self.process.returncode != 0:
            raise ValueError('native inspection exited unsuccessfully')


def _cleanup(process: subprocess.Popen[bytes], exchange: _ConfigExchange | None) -> Exception | None:
    failure = None
    try:
        _terminate_process_group(process)
    except Exception as error:
        failure = error
    resources = (exchange.selector if exchange is not None else None,
                 process.stdin, process.stdout, process.stderr)
    for resource in resources:
        if resource is not None:
            try:
                resource.close()
            except Exception as error:
                if failure is None:
                    failure = error
    return failure


def inspect_native_config(root: Path, *, binary: BinaryPin, timeout_seconds: float = 10,
                          max_output_bytes: int = 1024 * 1024,
                          disabled_servers: tuple[str, ...] = ()) -> ConfigInspection:
    if os.name != 'posix':
        raise ValueError('native configuration inspection currently requires POSIX')
    if not 0 < timeout_seconds <= 30 or type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 1024 * 1024:
        raise ValueError('invalid native inspection limits')
    verify_binary(binary)
    command = build_config_command(root, binary=binary, disabled_servers=disabled_servers)
    environment = _command_environment()
    try:
        process = subprocess.Popen(command, cwd=root, env=environment, shell=False,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0, start_new_session=True)
    except OSError as error:
        raise ConfigInspectionError(InspectionFailure('spawn', 'spawn_error', type(error).__name__,
            error.errno, None, None, None)) from None
    exchange, result, original, cleanup = None, None, None, None
    try:
        exchange = _ConfigExchange(process, time.monotonic() + timeout_seconds, max_output_bytes)
        result = exchange.configuration(root, binary, command, environment, disabled_servers)
    except Exception as error:
        original = error
    finally:
        cleanup = _cleanup(process, exchange)
    if original is not None or cleanup is not None:
        reason = {'native inspection timed out': 'timeout',
                  'native inspection output limit exceeded': 'output_limit'}.get(
                      str(original), 'exchange_error' if original else 'cleanup_error')
        raise ConfigInspectionError(InspectionFailure(exchange.stage if exchange and original else 'cleanup', reason,
            type(original).__name__ if original else None, getattr(original, 'errno', None),
            type(cleanup).__name__ if cleanup else None,
            getattr(cleanup, 'errno', None), process.poll())) from None
    if result is None:
        raise ValueError('native inspection result unavailable')
    return result
