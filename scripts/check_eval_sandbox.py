"""Check the effective candidate-tool sandbox without starting a model."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import sys
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from evals.native_runtime import PROFILE, runtime_readable_roots, sandbox_options, tool_environment
from evals.native_config import BinaryPin, trusted_binary_identity
from evals.runtime_trace import open_no_symlink
from scripts.command_runner import run_bounded_command

PROBE = r"""import json, os, socket, subprocess, sys
candidate, sentinel, outside, host_config, host_auth = sys.argv[1:6]
flags = sys.argv[6:8]
if len(sys.argv) != 8 or any(value not in {"0", "1"} for value in flags): raise SystemExit(2)
config_openable, auth_openable = (value == "1" for value in flags)
result = {}
try:
    with open(os.path.join(candidate, "probe-write.txt"), "x", encoding="utf-8") as stream: stream.write("ok")
    result["candidate_write"] = "allowed"
except OSError: result["candidate_write"] = "denied"
def opened(path):
    try: fd = os.open(path, os.O_RDONLY)
    except OSError: return "denied"
    os.close(fd); return "allowed"
result["synthetic_sentinel_open"] = opened(sentinel)
result["host_config_open"] = opened(host_config) if config_openable else "not_present"
result["host_auth_open"] = opened(host_auth) if auth_openable else "not_present"
try:
    fd = os.open(outside, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
    result["outside_write"] = "allowed"
except OSError: result["outside_write"] = "denied"
try:
    with socket.socket() as connection: connection.bind(("127.0.0.1", 0))
    result["loopback_bind"] = "allowed"
except OSError: result["loopback_bind"] = "denied"
child = r'''import json, os, sys
sentinel, outside = sys.argv[1:]
try: fd = os.open(sentinel, os.O_RDONLY)
except OSError: protected = "denied"
else: os.close(fd); protected = "allowed"
try: fd = os.open(outside, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd); write = "allowed"
except OSError: write = "denied"
print(json.dumps({"sentinel": protected, "outside_write": write}, sort_keys=True))
'''
try:
    child_result = subprocess.run([sys.executable, "-I", "-B", "-c", child, sentinel, outside],
                                  capture_output=True, text=True, timeout=5, check=False)
    child_state = json.loads(child_result.stdout) if child_result.returncode == 0 else {}
except (OSError, ValueError, subprocess.TimeoutExpired): child_state = {}
result["descendant_sentinel_open"] = child_state.get("sentinel", "unknown")
result["descendant_outside_write"] = child_state.get("outside_write", "unknown")
print(json.dumps(result, sort_keys=True))
"""


def validate_observation(observation: object, *, host_config_present: bool,
                         host_auth_present: bool) -> bool:
    if type(host_config_present) is not bool or type(host_auth_present) is not bool or \
            not isinstance(observation, dict):
        return False
    expected = {
        "candidate_write": "allowed",
        "synthetic_sentinel_open": "denied",
        "host_config_open": "denied" if host_config_present else "not_present",
        "host_auth_open": "denied" if host_auth_present else "not_present",
        "outside_write": "denied",
        "loopback_bind": "denied",
        "descendant_sentinel_open": "denied",
        "descendant_outside_write": "denied",
    }
    return set(observation) == set(expected) and observation == expected


def _sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _openable_without_reading(path: Path) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    os.close(descriptor)
    return True


def _host_loopback_bind_works() -> bool:
    try:
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0))
    except OSError:
        return False
    return True


def _version(codex: str, root: Path, environment: dict[str, str]) -> str:
    result = run_bounded_command([codex, "--version"], cwd=root, timeout_seconds=10,
                                 max_output_bytes=2048, env=environment)
    match = re.search(r"\bcodex-cli\s+(\S+)", result.output)
    if result.returncode != 0 or result.timed_out or result.output_limited or match is None:
        raise ValueError("Codex CLI version could not be identified")
    return match.group(1)


def _pin_executable(path: Path) -> tuple[BinaryPin, bytes, tuple[int, ...]]:
    path = path.resolve(strict=True)
    with os.fdopen(open_no_symlink(path), 'rb') as stream:
        before = os.fstat(stream.fileno())
        first_line = stream.readline(256)
        stream.seek(0)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or \
                not before.st_mode & 0o111 or not 0 < before.st_size <= 256 * 1024 * 1024:
            raise ValueError('Codex executable is not bounded, regular, and executable')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    identity = lambda metadata: (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
                                 metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_nlink)
    if identity(before) != identity(after):
        raise ValueError('Codex executable changed during verification')
    pin = BinaryPin(path, digest)
    protected_identity = trusted_binary_identity(pin)
    if protected_identity != identity(after):
        raise ValueError('Codex executable changed during trust verification')
    return pin, first_line.rstrip(b'\r\n'), protected_identity


def _trusted_codex(environment: dict[str, str]) -> tuple[BinaryPin, BinaryPin | None, tuple[int, ...], tuple[int, ...] | None]:
    found = shutil.which('codex')
    if found is None:
        raise ValueError('Codex CLI is unavailable')
    codex, shebang, codex_identity = _pin_executable(Path(found))
    node, node_identity = None, None
    if shebang.startswith(b'#!'):
        if shebang != b'#!/usr/bin/env node':
            raise ValueError('Codex CLI uses an unsupported interpreter')
        found_node = shutil.which('node', path=environment['PATH'])
        if found_node is None:
            raise ValueError('Codex CLI Node runtime is unavailable')
        node, _, node_identity = _pin_executable(Path(found_node))
    return codex, node, codex_identity, node_identity


def _verify_cli_identity(pin: BinaryPin, identity: tuple[int, ...]) -> None:
    if trusted_binary_identity(pin) != identity:
        raise ValueError('Codex executable changed during the sandbox probe')


def _scratch_root() -> Path:
    project_root = PROJECT_ROOT.resolve(strict=True)
    scratch = project_root / '.harness'
    if not stat.S_ISDIR(scratch.lstat().st_mode) or scratch.resolve(strict=True) != scratch:
        raise ValueError('sandbox scratch root must be a real directory inside the repository')
    return scratch


def check() -> dict[str, object]:
    host_config = Path.home() / ".codex/config.toml"
    host_auth = Path.home() / ".codex/auth.json"
    host_config_present, host_auth_present = host_config.is_file(), host_auth.is_file()
    if not host_config_present or not host_auth_present:
        raise ValueError('host Codex config or authentication file is absent; credential access is unmeasured')
    config_openable = host_config_present and _openable_without_reading(host_config)
    auth_openable = host_auth_present and _openable_without_reading(host_auth)
    if ((host_config_present and not config_openable) or
            (host_auth_present and not auth_openable)):
        raise ValueError("host Codex files are not readable by the trusted operator for a valid probe")
    if not _host_loopback_bind_works():
        raise ValueError("trusted host loopback bind control failed")
    scratch_root = _scratch_root()
    with TemporaryDirectory(prefix="eval-sandbox-", dir=scratch_root) as temporary:
        base = Path(temporary).resolve()
        candidate, sentinel = base / "candidate", base / "synthetic-sentinel"
        outside = base / "outside-write.txt"
        candidate.mkdir(mode=0o700)
        (candidate / ".eval-home").mkdir(mode=0o700)
        (candidate / ".eval-tmp").mkdir(mode=0o700)
        sentinel.write_bytes(b"synthetic-only\n")
        sentinel.chmod(0o600)
        if not _openable_without_reading(sentinel):
            raise ValueError("trusted synthetic sentinel control failed")
        outside_control = base / "outside-control.txt"
        outside_control.write_bytes(b"")
        outside_control.unlink()
        environment = tool_environment(candidate)
        codex, node, codex_identity, node_identity = _trusted_codex(environment)
        options = sandbox_options(writable=True, readable_roots=runtime_readable_roots())
        command = [str(codex.path), "sandbox", "--permission-profile", PROFILE, "-C", str(candidate), *options,
                   "/usr/bin/env", "-i", *(f"{key}={value}" for key, value in environment.items()),
                   sys.executable, "-I", "-B", "-c", PROBE, str(candidate), str(sentinel), str(outside),
                   str(host_config), str(host_auth), "1" if config_openable else "0",
                   "1" if auth_openable else "0"]
        policy_sha256 = _sha256(list(options))
        result = run_bounded_command(command, cwd=candidate, timeout_seconds=30,
                                     max_output_bytes=65536, env=environment)
        if result.returncode != 0 or result.timed_out or result.output_limited:
            raise ValueError("Codex sandbox probe did not complete successfully")
        try:
            observation = json.loads(result.output.splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            raise ValueError("Codex sandbox probe returned invalid output") from None
        if not validate_observation(observation, host_config_present=host_config_present,
                                    host_auth_present=host_auth_present):
            raise ValueError("Codex sandbox probe did not establish the required boundary")
        if not (candidate / "probe-write.txt").is_file():
            raise ValueError("candidate write control was not materialized")
        version = _version(str(codex.path), candidate, environment)
        _verify_cli_identity(codex, codex_identity)
        if node is not None and node_identity is not None:
            _verify_cli_identity(node, node_identity)
        return {
            "schema": 1,
            "passed": True,
            "profile": PROFILE,
            "codex_cli_version": version,
            "codex_cli_binary_sha256": codex.sha256,
            "codex_runtime_binary_sha256": node.sha256 if node is not None else None,
            "policy_sha256": policy_sha256,
            "command_sha256": _sha256(command),
            "environment_sha256": _sha256(environment),
            "host_config_present": host_config_present,
            "host_auth_file_present": host_auth_present,
            "trusted_controls": {
                "host_config_open_without_read": "allowed" if config_openable else "not_present",
                "host_auth_open_without_read": "allowed" if auth_openable else "not_present",
                "sentinel_open_without_read": "allowed",
                "outside_write": "allowed",
                "loopback_bind": "allowed",
            },
            "observed": observation,
            "scope": {
                "model_started": False,
                "codex_parent": "trusted_outside_tool_sandbox",
                "descendant_cleanup": "not_measured",
                "hooks": "not_measured",
                "mcp": "not_measured",
            },
        }


def main() -> int:
    try:
        report = check()
    except OSError:
        report = {"schema": 1, "passed": False, "failure": "preflight_io_error"}
    except ValueError as error:
        report = {"schema": 1, "passed": False, "failure": str(error)}
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
