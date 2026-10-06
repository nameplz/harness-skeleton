"""Git-based risk classification kept separate from CLI and validation setup."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
import fnmatch
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from .command_runner import run_bounded_command
    from .harness_common import HarnessError, sanitize_log
except ImportError:  # Direct script invocation from the scripts directory.
    from command_runner import run_bounded_command
    from harness_common import HarnessError, sanitize_log

MAX_DIFF_BYTES = 8 * 1024 * 1024
MAX_UNTRACKED_FILE_BYTES = 1024 * 1024
DEFAULT_SECURITY_PATHS = (
    ".github",
    ".github/**",
    ".codex",
    ".codex/**",
    ".harness",
    ".harness/**",
    "deploy",
    "deploy/**",
    "auth",
    "auth/**",
    "**/auth/**",
    "security",
    "security/**",
    "**/security/**",
    "migrations",
    "migrations/**",
    "**/migrations/**",
    "*.sql",
    "**/*.sql",
    "scripts/harness.py",
    "scripts/harness_common.py",
    "scripts/harness_risk.py",
    "scripts/*validation*.py",
    "scripts/check_*.py",
)
DEFAULT_SECURITY_KEYWORDS = (
    "subprocess",
    "shell",
    "exec",
    "spawn",
    "network",
    "http",
    "credential",
    "secret",
    "token",
    "user-controlled path",
    "user_supplied",
    "write_text",
    "open(",
    "permission",
    "authentication",
    "authorization",
)
DEPENDENCY_FILES = frozenset(
    {
        "cargo.lock",
        "cargo.toml",
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)
COMPLEXITY_MARKERS = ("public api", "public interface", "new subsystem", "cross-module")


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    code_review: bool
    security_review: bool
    reasons: tuple[str, ...]
    changed_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        result["changed_paths"] = list(self.changed_paths)
        return result


def classify_risk(
    paths: Sequence[str],
    diff_text: str,
    *,
    security_paths: Sequence[str] = DEFAULT_SECURITY_PATHS,
    security_keywords: Sequence[str] = DEFAULT_SECURITY_KEYWORDS,
) -> RiskAssessment:
    """Classify changes conservatively for review routing."""

    changed_paths = validate_relative_paths(paths)
    if not isinstance(diff_text, str):
        raise HarnessError("diff content must be text")
    configured_paths = _merge_patterns(DEFAULT_SECURITY_PATHS, security_paths, "security_paths")
    configured_keywords = _merge_keywords(DEFAULT_SECURITY_KEYWORDS, security_keywords)
    changed_text = _changed_lines(diff_text).casefold()

    reasons: list[str] = []
    for path in changed_paths:
        if any(fnmatch.fnmatchcase(path.casefold(), pattern.casefold()) for pattern in configured_paths):
            reasons.append(f"changed security-sensitive path: {path}")
    for keyword in configured_keywords:
        if keyword.casefold() in changed_text:
            reasons.append(f"security-sensitive keyword detected: {keyword}")

    if not changed_paths:
        reasons.append("no changes detected")
        return RiskAssessment("T0", False, False, tuple(reasons), ())

    if reasons:
        return RiskAssessment("T3", True, True, tuple(dict.fromkeys(reasons)), changed_paths)

    if all(_is_documentation_path(path) for path in changed_paths):
        return RiskAssessment("T0", False, False, ("documentation-only changes",), changed_paths)

    complexity_reasons = _complexity_reasons(changed_paths, changed_text)
    if complexity_reasons:
        return RiskAssessment("T2", True, False, tuple(complexity_reasons), changed_paths)
    return RiskAssessment("T1", False, False, ("focused change",), changed_paths)


def validate_relative_paths(paths: Sequence[str]) -> tuple[str, ...]:
    if isinstance(paths, (str, bytes)) or not isinstance(paths, Sequence):
        raise HarnessError("changed paths must be a list of relative paths")
    normalized: list[str] = []
    for value in paths:
        if not isinstance(value, str) or not value:
            raise HarnessError("changed path must be a non-empty string")
        path = value.replace("\\", "/")
        if (
            path.startswith(("/", "~"))
            or re.match(r"^[A-Za-z]:", path)
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or "\x00" in path
        ):
            raise HarnessError(f"unsafe changed path: {value}")
        if any(part in {"", ".", ".."} for part in path.split("/")):
            raise HarnessError(f"unsafe changed path: {value}")
        canonical = PurePosixPath(path).as_posix()
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)


def _merge_patterns(defaults: Sequence[str], custom: Sequence[str], name: str) -> tuple[str, ...]:
    values = _validate_pattern_list(custom, name)
    return tuple(dict.fromkeys((*defaults, *values)))


def _validate_pattern_list(values: Sequence[str], name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise HarnessError(f"{name} must be a list of relative glob patterns")
    patterns: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise HarnessError(f"{name} entries must be non-empty strings")
        pattern = value.strip().replace("\\", "/")
        if (
            pattern.startswith(("/", "~"))
            or re.match(r"^[A-Za-z]:", pattern)
            or any(ord(char) < 32 or ord(char) == 127 for char in pattern)
            or any(part in {"", ".", ".."} for part in pattern.split("/"))
        ):
            raise HarnessError(f"unsafe {name} pattern: {value}")
        if pattern not in patterns:
            patterns.append(pattern)
    return tuple(patterns)


def _merge_keywords(defaults: Sequence[str], custom: Sequence[str]) -> tuple[str, ...]:
    if isinstance(custom, (str, bytes)) or not isinstance(custom, Sequence):
        raise HarnessError("security_keywords must be a list of strings")
    keywords: list[str] = list(defaults)
    for value in custom:
        if not isinstance(value, str) or not value.strip():
            raise HarnessError("security_keywords entries must be non-empty strings")
        keyword = value.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in keyword):
            raise HarnessError("security_keywords entries cannot contain control characters")
        if keyword.casefold() not in {item.casefold() for item in keywords}:
            keywords.append(keyword)
    return tuple(keywords)


def _changed_lines(diff_text: str) -> str:
    lines = [
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    return "\n".join(lines) if lines else diff_text


def _is_documentation_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    if candidate.suffix.casefold() not in {".md", ".mdx", ".rst", ".txt"}:
        return False
    return candidate.parts[0].casefold() == "docs" or candidate.name.casefold().startswith("readme")


def _is_test_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    parts = {part.casefold() for part in candidate.parts[:-1]}
    name = candidate.name.casefold()
    return bool(parts & {"test", "tests", "__tests__", "e2e"}) or (
        name.startswith("test_") or ".test." in name or ".spec." in name
    )


def _complexity_reasons(paths: Sequence[str], changed_text: str) -> list[str]:
    reasons: list[str] = []
    source_paths = [path for path in paths if not _is_documentation_path(path) and not _is_test_path(path)]
    if len(source_paths) >= 2:
        reasons.append("changes span multiple implementation files")
    if any("api" in {part.casefold() for part in PurePosixPath(path).parts[:-1]} for path in source_paths):
        reasons.append("changed a public API area")
    if any(PurePosixPath(path).name.casefold() in DEPENDENCY_FILES for path in paths):
        reasons.append("changed dependency declarations")
    for marker in COMPLEXITY_MARKERS:
        if marker in changed_text:
            reasons.append(f"complex change marker: {marker}")
    return reasons


def _git_output(root: Path, arguments: Sequence[str], *, timeout: int = 30) -> str:
    try:
        completed = run_bounded_command(
            ["git", *arguments],
            cwd=root,
            timeout_seconds=timeout,
            max_output_bytes=MAX_DIFF_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError("could not inspect Git changes: " + sanitize_log(str(exc))) from exc
    if completed.output_limited:
        raise HarnessError("Git output exceeds the risk scan limit")
    if completed.timed_out:
        raise HarnessError("Git command timed out during risk scan")
    if completed.returncode != 0:
        raise HarnessError("could not inspect Git changes: " + sanitize_log(completed.output.strip()))
    return completed.output


def _git_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    result = _git_output(resolved, ["rev-parse", "--show-toplevel"])
    try:
        return Path(result.strip()).resolve(strict=True)
    except OSError as exc:
        raise HarnessError("Git repository root is unavailable") from exc


def inspect_git_risk(
    root: Path,
    *,
    load_config_fn: Callable[[Path], Any],
) -> RiskAssessment:
    workspace = root.resolve(strict=True)
    repository = _git_root(workspace)
    try:
        workspace.relative_to(repository)
    except ValueError as exc:
        raise HarnessError("workspace root must be inside its Git repository") from exc
    if _git_has_head(repository):
        tracked_paths = _git_output(
            workspace,
            ["diff", "--relative", "--no-renames", "--name-only", "-z", "--no-ext-diff", "HEAD", "--", "."],
        ).split("\0")
        diff_text = _git_output(
            workspace,
            [
                "diff",
                "--relative",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--unified=0",
                "HEAD",
                "--",
                ".",
            ],
        )
    else:
        staged_paths = _git_output(
            workspace,
            [
                "diff",
                "--relative",
                "--cached",
                "--no-renames",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--",
                ".",
            ],
        ).split("\0")
        unstaged_paths = _git_output(
            workspace,
            ["diff", "--relative", "--no-renames", "--name-only", "-z", "--no-ext-diff", "--", "."],
        ).split("\0")
        tracked_paths = [*staged_paths, *unstaged_paths]
        diff_text = _git_output(
            workspace,
            [
                "diff",
                "--relative",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--unified=0",
                "--",
                ".",
            ],
        )
        diff_text += _git_output(
            workspace,
            [
                "diff",
                "--relative",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--unified=0",
                "--",
                ".",
            ],
        )
    untracked_paths = _git_output(
        workspace, ["ls-files", "--others", "--exclude-standard", "-z", "--", "."]
    ).split("\0")
    paths = [path for path in (*tracked_paths, *untracked_paths) if path]
    diff_size_bytes = len(diff_text.encode("utf-8"))
    if diff_size_bytes > MAX_DIFF_BYTES:
        raise HarnessError("Git diff exceeds the risk scan limit")
    for relative in untracked_paths:
        if not relative:
            continue
        normalized = validate_relative_paths((relative,))[0]
        candidate = workspace / normalized
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(workspace)
        except ValueError as exc:
            raise HarnessError(f"untracked path resolves outside workspace: {normalized}") from exc
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            content = candidate.read_bytes()
        except OSError as exc:
            raise HarnessError(f"could not read untracked path: {normalized}") from exc
        if len(content) > MAX_UNTRACKED_FILE_BYTES:
            raise HarnessError(f"untracked file exceeds risk scan limit: {normalized}")
        addition = "\n" + "\n".join(
            "+" + line for line in content.decode("utf-8", errors="replace").splitlines()
        )
        addition_size = len(addition.encode("utf-8"))
        if diff_size_bytes + addition_size > MAX_DIFF_BYTES:
            raise HarnessError("Git diff exceeds the risk scan limit")
        diff_text += addition
        diff_size_bytes += addition_size
    config_path = workspace / ".harness/config.toml"
    if config_path.exists() or config_path.is_symlink():
        config = load_config_fn(workspace)
        return classify_risk(
            paths,
            diff_text,
            security_paths=config.security_paths,
            security_keywords=config.security_keywords,
        )
    return classify_risk(paths, diff_text)


def _git_has_head(repository: Path) -> bool:
    try:
        _git_output(repository, ["rev-parse", "--verify", "HEAD"], timeout=5)
    except HarnessError:
        return False
    return True
