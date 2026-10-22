"""Run candidate hook code under Codex's candidate-only OS sandbox."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from evals.native_runtime import PROFILE, runtime_readable_roots, sandbox_options, tool_environment  # noqa: E402
from evals.runtime_trace import open_no_symlink  # noqa: E402
from scripts.check_eval_sandbox import _trusted_codex, _verify_cli_identity  # noqa: E402
from scripts.command_runner import CommandResult, run_bounded_command  # noqa: E402

MAX_HOOK_OUTPUT_BYTES = 1024 * 1024
MAX_HOOK_INPUT_BYTES = 1024 * 1024
MAX_HOOK_SOURCE_BYTES = 1024 * 1024
MAX_WORKSPACE_ENTRIES = 100_000
SAFE_ENV_KEYS = frozenset({"PATH", "HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE"})
HOOK_BOOTSTRAP = (
    "import sys\n"
    "source = open(sys.argv[1], 'rb').read()\n"
    "filename = sys.argv[2]\n"
    "sys.argv = [filename]\n"
    "exec(compile(source, filename, 'exec'), "
    "{'__name__': '__main__', '__file__': filename})\n"
)


def validate_event_input(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) > MAX_HOOK_INPUT_BYTES:
        raise ValueError("hook event input exceeds its byte limit")
    try:
        event = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("hook event input must be valid JSON") from None
    if not isinstance(event, dict) or not isinstance(event.get("hook_event_name"), str) or \
            not event["hook_event_name"]:
        raise ValueError("hook event input must contain a hook_event_name")
    return value


def resolve_hook(workspace: Path, relative: str) -> Path:
    """Resolve a regular, non-symlink hook within a real workspace."""

    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("hook path must be a non-empty relative path")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError("hook path must stay within the workspace")
    if Path(workspace).is_symlink():
        raise ValueError("workspace cannot be a symlink")
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("workspace must be a directory")
    target = root
    for index, part in enumerate(parsed.parts):
        target = target / part
        try:
            metadata = target.lstat()
        except OSError:
            raise ValueError("hook path is unavailable") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("hook path cannot contain symlinks")
        if index < len(parsed.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("hook parent must be a directory")
    metadata = target.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("hook must be a regular file")
    if metadata.st_nlink != 1:
        raise ValueError("hook cannot be a hardlink")
    if metadata.st_size > MAX_HOOK_SOURCE_BYTES:
        raise ValueError("hook source exceeds its size limit")
    return target


def build_command(
    codex: Path,
    workspace: Path,
    hook: Path,
    snapshot_root: Path,
    snapshot: Path,
    environment: dict[str, str],
) -> list[str]:
    if set(environment) != SAFE_ENV_KEYS or "CODEX_HOME" in environment:
        raise ValueError("hook environment must contain only the isolated allowlist")
    if any(not value or "\x00" in value for value in environment.values()):
        raise ValueError("hook environment contains an invalid value")
    root = workspace.resolve(strict=True)
    if not hook.is_absolute():
        raise ValueError("hook path must be absolute")
    hook_path = hook.resolve(strict=True)
    if hook.absolute() != hook_path:
        raise ValueError("hook path must not contain symlinks")
    try:
        hook_path.relative_to(root)
    except ValueError:
        raise ValueError("hook must stay within the workspace") from None
    command = [
        str(codex), "sandbox", "--permission-profile", PROFILE, "-C", str(root),
        *sandbox_options(writable=True, readable_roots=(*runtime_readable_roots(), snapshot_root)),
        "/usr/bin/env", "-i", *(f"{key}={environment[key]}" for key in sorted(environment)),
        str(Path(sys.executable).resolve(strict=True)), "-I", "-B", "-c", HOOK_BOOTSTRAP,
        str(snapshot), str(hook_path),
    ]
    return command


def _scratch_directory(workspace: Path) -> Path:
    scratch = workspace / ".harness"
    metadata = scratch.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or scratch.resolve(strict=True) != scratch:
        raise ValueError("workspace .harness directory must be real and canonical")
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("workspace .harness directory must be private and belong to the operator")
    return scratch


def _canonical_directory(path: Path, name: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(f"{name} must be a real canonical directory") from None
    if absolute != resolved or not resolved.is_dir():
        raise ValueError(f"{name} must be a real canonical directory")
    return resolved


def _validate_workspace_tree(root: Path) -> None:
    root_device = root.stat().st_dev
    pending = [root]
    checked = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    checked += 1
                    if checked > MAX_WORKSPACE_ENTRIES:
                        raise ValueError("workspace tree exceeds its entry limit")
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError:
                        raise ValueError("workspace tree changed during inspection") from None
                    if stat.S_ISLNK(metadata.st_mode):
                        try:
                            Path(entry.path).resolve(strict=True).relative_to(root)
                        except (OSError, RuntimeError, ValueError):
                            raise ValueError("workspace symlink must resolve within the workspace") from None
                    elif stat.S_ISDIR(metadata.st_mode):
                        # shortcut: same-device bind mounts can evade ismount; accept only operator-created scratch trees.
                        if metadata.st_dev != root_device or os.path.ismount(entry.path):
                            raise ValueError("workspace cannot contain a mounted directory")
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(metadata.st_mode):
                        if metadata.st_nlink != 1:
                            raise ValueError("workspace cannot contain hardlinks")
                    else:
                        raise ValueError("workspace cannot contain special files")
        except OSError:
            raise ValueError("workspace tree could not be inspected") from None


def _snapshot_hook(hook: Path, destination: Path) -> None:
    try:
        descriptor = open_no_symlink(hook)
    except OSError:
        raise ValueError("hook source could not be opened safely") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or \
                before.st_size > MAX_HOOK_SOURCE_BYTES:
            raise ValueError("hook source identity or size is invalid")
        source = stream.read(MAX_HOOK_SOURCE_BYTES + 1)
        after = os.fstat(stream.fileno())
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
                                 item.st_ctime_ns, item.st_nlink)
        if len(source) > MAX_HOOK_SOURCE_BYTES or identity(before) != identity(after):
            raise ValueError("hook source changed while it was snapshotted")
    destination.write_bytes(source)
    destination.chmod(0o400)


def run_hook(
    workspace: Path,
    hook_relative: str,
    *,
    scratch_root: Path,
    event_input: bytes,
    timeout_seconds: int = 180,
) -> CommandResult:
    if sys.platform not in {"darwin", "linux"}:
        raise ValueError("isolated hook execution requires macOS or Linux Codex sandbox support")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 180:
        raise ValueError("hook timeout must be from 1 to 180 seconds")
    event_input = validate_event_input(event_input)
    scratch_root = _canonical_directory(Path(scratch_root), "operator scratch root")
    scratch_metadata = scratch_root.lstat()
    if scratch_metadata.st_uid != os.getuid() or scratch_metadata.st_mode & 0o077:
        raise ValueError("operator scratch root must be private and belong to the operator")
    root = _canonical_directory(Path(workspace), "workspace")
    try:
        root.relative_to(scratch_root)
    except ValueError:
        raise ValueError("workspace must be under the operator scratch root") from None
    if root == scratch_root:
        raise ValueError("workspace must be a child of the operator scratch root")
    workspace_metadata = root.lstat()
    if workspace_metadata.st_uid != os.getuid() or workspace_metadata.st_mode & 0o077:
        raise ValueError("workspace must be private and belong to the operator")
    if workspace_metadata.st_dev != scratch_metadata.st_dev or os.path.ismount(root):
        raise ValueError("workspace must be on the operator scratch filesystem")
    _validate_workspace_tree(root)
    hook = resolve_hook(root, hook_relative)
    workspace_scratch = _scratch_directory(root)
    environment = tool_environment(root)
    codex, node, codex_identity, node_identity = _trusted_codex(environment)
    with tempfile.TemporaryDirectory(prefix="isolated-hook-source-", dir=scratch_root) as source_dir, \
            tempfile.TemporaryDirectory(prefix="isolated-hook-", dir=workspace_scratch) as temporary:
        snapshot_root = Path(source_dir)
        snapshot = snapshot_root / "hook.py"
        _snapshot_hook(hook, snapshot)
        temporary_root = Path(temporary)
        home, temp = temporary_root / "home", temporary_root / "tmp"
        home.mkdir(mode=0o700)
        temp.mkdir(mode=0o700)
        environment.update({"HOME": str(home), "TMPDIR": str(temp)})
        command = build_command(codex.path, root, hook, snapshot_root, snapshot, environment)
        result = run_bounded_command(command, cwd=root, timeout_seconds=timeout_seconds,
                                     max_output_bytes=MAX_HOOK_OUTPUT_BYTES, env=environment,
                                     input_bytes=event_input)
    _verify_cli_identity(codex, codex_identity)
    if node is not None and node_identity is not None:
        _verify_cli_identity(node, node_identity)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True,
                        help="operator-created private parent containing the disposable workspace")
    parser.add_argument("--hook", required=True, help="candidate-relative hook script path")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(argv)
    try:
        if sys.stdin.isatty():
            raise ValueError("hook event stdin cannot be a terminal")
        event_input = validate_event_input(sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1))
        result = run_hook(args.workspace, args.hook, scratch_root=args.scratch_root,
                          event_input=event_input, timeout_seconds=args.timeout_seconds)
    except (OSError, RuntimeError, ValueError, AttributeError):
        print("isolated hook did not run", file=sys.stderr)
        return 125
    sys.stdout.write(result.output)
    if result.timed_out:
        return 124
    if result.output_limited:
        return 125
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
