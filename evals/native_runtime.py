"""Pinned CLI commands for trusted operators; actual confinement needs a host probe."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import sysconfig
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evals.runtime_invocation import Invocation

PROFILE = "harness-eval"


def runtime_readable_roots(*, native_binary: Path | None = None) -> tuple[Path, ...]:
    if native_binary is not None and (not isinstance(native_binary, Path)
            or not native_binary.is_absolute() or '..' in native_binary.parts):
        raise ValueError('native reexecution requires an absolute binary path')
    python_paths = (Path(sys.executable).absolute().parent, Path(sys.executable).resolve().parent,
                    Path(sysconfig.get_path('stdlib')).resolve())
    apple_tools = Path("/Library/Developer/CommandLineTools/usr")
    git_paths = (apple_tools / 'bin', apple_tools / 'libexec/git-core')
    # _ctypes may load libffi outside stdlib; grant only in-LIBDIR files.
    libdir = sysconfig.get_config_var('LIBDIR')
    libffi_paths = ()
    if sys.platform == 'darwin' and isinstance(libdir, str) and Path(libdir).is_absolute():
        library_root = Path(libdir).resolve()
        libffi_paths = tuple(sorted({resolved for path in library_root.glob('libffi*.dylib')
                                     if path.is_file()
                                     for resolved in (path.resolve(),)
                                     if resolved.is_relative_to(library_root)}))
    # Linux bubblewrap re-executes this file inside the restricted filesystem.
    native_paths = (native_binary,) if sys.platform == 'linux' and native_binary is not None else ()
    return (*python_paths, *(path for path in git_paths if path.exists()), *libffi_paths, *native_paths)


def sandbox_options(*, writable: bool, readable_roots: tuple[Path, ...] = ()) -> tuple[str, ...]:
    filesystem = {":root": "deny", ":minimal": "read", ":tmpdir": "deny", ":slash_tmp": "deny"}
    for path in readable_roots:
        if not path.is_absolute():
            raise ValueError("readable roots must be absolute")
        filesystem[str(path.absolute())] = "read"
        filesystem[str(path.resolve())] = "read"
    # Candidate probes use isolated stdlib Python; optional installed packages are not a read grant.
    packages = Path(sysconfig.get_path('purelib')).resolve()
    if any(packages.is_relative_to(path.resolve()) for path in readable_roots):
        filesystem[str(packages)] = 'deny'
    entries = [f"{json.dumps(key)}={json.dumps(value)}" for key, value in filesystem.items()]
    access = "write" if writable else "read"
    entries.append(f'":workspace_roots"={{"."="{access}",".eval-home"="read"}}')
    inline = "{" + ",".join(entries) + "}"
    parent = ":workspace" if writable else ":read-only"
    return (
        "-c", f'default_permissions="{PROFILE}"',
        "-c", f'permissions.{PROFILE}.extends="{parent}"',
        "-c", f"permissions.{PROFILE}.filesystem={inline}",
        "-c", f"permissions.{PROFILE}.network.enabled=false",
        "-c", 'shell_environment_policy.inherit="none"',
    )


def tool_environment(root: Path) -> dict[str, str]:
    """The same explicit environment is used for model tools and native grading."""
    apple_git = "/Library/Developer/CommandLineTools/usr/bin:"
    git_path = apple_git if Path(apple_git[:-1]).is_dir() else ""
    return {"PATH": f"{Path(sys.executable).parent}:{git_path}/usr/local/bin:/usr/bin:/bin",
            "HOME": str(root / ".eval-home"), "TMPDIR": str(root / ".eval-tmp"),
            "PYTHONDONTWRITEBYTECODE": "1"}


def build_exec_command(root: Path, *, model: str, writable: bool, invocation: Invocation | None = None) -> tuple[str, ...]:
    from evals.runtime_invocation import Invocation, verify_invocation
    from evals.runtime_boundary import require_read_grants, fixture_protection
    if not isinstance(invocation, Invocation):
        raise ValueError('native model execution requires a host-issued invocation and source preflight')
    verify_invocation(invocation.fixture, invocation)
    root = root.resolve()
    if root != invocation.execution_root or model != invocation.model or writable != (invocation.kind == 'worker'):
        raise ValueError('native command does not match its invocation')
    readable = runtime_readable_roots()
    require_read_grants(fixture_protection(invocation.fixture), readable)
    # Keep authentication in the CLI parent; tool children get synthetic HOME and no inherited secrets.
    environment = {**tool_environment(root), 'HARNESS_EVAL_NONCE': invocation.nonce,
                   'HARNESS_EVAL_INVOCATION_SHA256': invocation.sha256}
    values = "{" + ",".join(f"{json.dumps(key)}={json.dumps(value)}" for key, value in environment.items()) + "}"
    return (
        "codex", "exec", "--ignore-user-config", "--ignore-rules", "--strict-config",
        "--model", model, "--json", "-C", str(root),
        *sandbox_options(writable=writable, readable_roots=readable),
        "-c", 'approval_policy="never"', "-c", 'model_reasoning_effort="high"',
        "-c", 'web_search="disabled"',
        "-c", 'features.hooks=false', "-c", 'features.apps=false',
        "-c", 'features.plugins=false', "-c", 'apps._default.enabled=false',
        "-c", f"shell_environment_policy.set={values}",
        "-c", "projects={" + json.dumps(str(root)) + '={trust_level="untrusted"}}',
    )


def build_review_command(root: Path, *, model: str, invocation: Invocation | None = None) -> tuple[str, ...]:
    # Review snapshots contain source only; no candidate hooks or delegated tool policy may execute.
    return (*build_exec_command(root, model=model, writable=False, invocation=invocation), '--skip-git-repo-check',
            '-c', 'features.multi_agent=false', '-c', 'agents.enabled=false',
            '-c', 'projects.' + json.dumps(str(root.resolve())) + '.trust_level="untrusted"')


def worker_prompt(invocation: Invocation) -> str:
    return (invocation.fixture.prompt + '\nThis is a local-only isolated evaluation. '
            'Do not create external issues, messages or publications. Preserve existing user work. '
            f'Host invocation nonce: {invocation.nonce}; identity SHA256: {invocation.sha256}.')
