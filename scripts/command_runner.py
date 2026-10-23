"""Run validation commands with bounded output, time, and process-group cleanup."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence


_SAFE_ENV_KEYS = frozenset(
    {
        "PATH", "HOME", "CODEX_HOME", "USER", "LOGNAME", "SHELL", "LANG",
        "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT",
        "WINDIR", "PATHEXT", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
        "PYTHONDONTWRITEBYTECODE", "NO_COLOR", "FORCE_COLOR", "COLORTERM",
    }
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str
    timed_out: bool = False
    output_limited: bool = False
    output_bytes: bytes | None = None
    started: bool = True


def _is_git_executable(value: str) -> bool:
    return Path(value.replace("\\", "/")).name.casefold() in {"git", "git.exe"}


def _git_subcommand_index(arguments: Sequence[str]) -> int | None:
    options_with_values = {
        "-C",
        "-c",
        "--config",
        "--config-env",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--exec-path",
    }
    options_without_values = {
        "--bare", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
        "--no-optional-locks", "--literal-pathspecs",
    }
    position = 0
    while position < len(arguments):
        argument = arguments[position]
        if argument in options_with_values:
            position += 2
        elif argument in options_without_values or argument.startswith(
            (
                "--config=",
                "--config-env=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--exec-path=",
            )
        ):
            position += 1
        elif argument.startswith(("-C", "-c")) and len(argument) > 2:
            position += 1
        elif argument.startswith("-"):
            position += 1
        else:
            return position
    return None


def run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_output_bytes: int,
    env: Mapping[str, str] | None = None,
    binary_output: bool = False,
) -> CommandResult:
    """Capture at most max_output_bytes and stop a process group on timeout."""

    if timeout_seconds <= 0 or max_output_bytes < 1:
        raise ValueError("command limits must be positive")
    deadline = time.monotonic() + timeout_seconds
    if argv and not _is_git_executable(argv[0]) and any(_is_git_executable(arg) for arg in argv[1:]):
        return CommandResult(125, "Wrapped Git inspection is unsupported; invoke Git directly", started=False)
    if argv and _is_git_executable(argv[0]):
        index = _git_subcommand_index(argv[1:])
        if index is not None and argv[index + 1] in {"status", "diff"}:
            # shortcut: preflight is not atomic against local config writes; host isolation must cover hostile concurrency.
            probe = run_bounded_command(
                [*argv[:index + 1], "config", "--includes", "--null", "--name-only",
                 "--get-regexp", r"^filter\..*\.(clean|smudge|process)$"],
                cwd=cwd, timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes, env=env,
            )
            if probe.returncode != 1 or probe.output or probe.timed_out or probe.output_limited:
                return CommandResult(124 if probe.timed_out and not probe.output_limited else 125,
                                     "Git inspection blocked: callback configuration could not be excluded",
                                     timed_out=probe.timed_out, output_limited=probe.output_limited, started=False)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return CommandResult(124, "Git inspection preflight timed out", timed_out=True, started=False)
            # Dirty submodules run nested Git with separate callback configuration.
            args = list(argv[index + 2:])
            boundary = args.index("--") if "--" in args else len(args)
            options = [arg for arg in args[:boundary]
                       if arg != "--ignore-submodules" and not arg.startswith("--ignore-submodules=")]
            if argv[index + 1] == "diff":
                options = [arg for arg in options if arg not in {"--ext-diff", "--textconv"}]
                options.extend(["--no-ext-diff", "--no-textconv"])
            argv = [*argv[:index + 1], "-c", "core.fsmonitor=false", argv[index + 1],
                    *options, "--ignore-submodules=dirty", *args[boundary:]]
    environment = _command_environment(env)
    kwargs: dict[str, object] = {
        "cwd": cwd,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "shell": False,
        "bufsize": 0,
        "env": environment,
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True
    elif os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    process = subprocess.Popen(list(argv), **kwargs)
    if process.stdout is None:
        raise OSError("check command output could not be captured")

    captured = bytearray()
    output_limited = threading.Event()

    def collect_output() -> None:
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                return
            remaining = max_output_bytes - len(captured)
            if remaining > 0:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                output_limited.set()

    reader = threading.Thread(target=collect_output, name="harness-check-output", daemon=True)
    reader.start()
    timed_out = False

    while process.poll() is None:
        if output_limited.is_set():
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break
        time.sleep(0.02)

    if process.poll() is None and (timed_out or output_limited.is_set()):
        _terminate_process_group(process)
    reader.join(timeout=0.2)
    if reader.is_alive():
        _terminate_process_group(process)
        reader.join(timeout=2)
        timed_out = True
    try:
        process.stdout.close()
    except OSError:
        pass

    raw_output = bytes(captured)
    output = "" if binary_output else raw_output.decode("utf-8", errors="replace")
    captured_bytes = raw_output if binary_output else None
    if output_limited.is_set():
        return CommandResult(125, output, output_limited=True, output_bytes=captured_bytes)
    if timed_out:
        return CommandResult(124, output, timed_out=True, output_bytes=captured_bytes)
    return CommandResult(process.returncode or 0, output, output_bytes=captured_bytes)


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.terminate()

    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _command_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if base is None else base
    environment = {
        key: value for key, value in source.items() if key in _SAFE_ENV_KEYS
    }
    environment.update(
        {
            "GIT_CONFIG_COUNT": "8",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "core.pager",
            "GIT_CONFIG_VALUE_2": "cat",
            "GIT_CONFIG_KEY_3": "protocol.allow",
            "GIT_CONFIG_VALUE_3": "never",
            "GIT_CONFIG_KEY_4": "protocol.ext.allow",
            "GIT_CONFIG_VALUE_4": "never",
            "GIT_CONFIG_KEY_5": "diff.external",
            "GIT_CONFIG_VALUE_5": "",
            "GIT_CONFIG_KEY_6": "core.gitproxy",
            "GIT_CONFIG_VALUE_6": "",
            "GIT_CONFIG_KEY_7": "credential.helper",
            "GIT_CONFIG_VALUE_7": "",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment
