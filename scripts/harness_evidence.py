"""Bounded Git fingerprints for validation evidence, not execution attestations."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

try:
    from .harness_common import HarnessError
    from .harness_risk import MAX_DIFF_BYTES, _git_output, _read_untracked_file
except ImportError:  # Direct trusted script invocation.
    from harness_common import HarnessError
    from harness_risk import MAX_DIFF_BYTES, _git_output, _read_untracked_file


def capture_workspace(root: Path) -> dict[str, Any]:
    known_git = any((directory / ".git").exists() or (directory / ".git").is_symlink()
                    for directory in (root, *root.parents))
    unknown = {"status": "error" if known_git else "unavailable", "head": None, "dirty": None, "diff_sha256": None}
    deadline = time.monotonic() + 5

    def git(arguments: list[str]) -> str:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HarnessError("workspace evidence timed out")
        return _git_output(root, arguments, timeout=remaining)

    try:
        workspace = root.resolve(strict=True)
        workspace.relative_to(Path(git(["rev-parse", "--show-toplevel"]).strip()).resolve(strict=True))
        unknown["status"] = "error"
        try:
            head = git(["rev-parse", "--verify", "HEAD"]).strip()
        except HarnessError:
            head = None  # An unborn repository has useful dirty evidence but no HEAD.
        status = git(["status", "--porcelain=v1", "-z", "--", "."])
        diff_args = ["diff", "--binary", "--no-ext-diff", "--no-textconv", "--no-color"]
        if head is not None:
            diffs = [git([*diff_args, "HEAD", "--", "."])]
        else:
            diffs = [git([*diff_args, "--cached", "--", "."]), git([*diff_args, "--", "."])]
        chunks = [status.encode("utf-8"), *(diff.encode("utf-8") for diff in diffs)]
        total_bytes = sum(len(chunk) for chunk in chunks)
        fingerprint = hashlib.sha256()
        for chunk in chunks:
            fingerprint.update(hashlib.sha256(chunk).digest())
        untracked = git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."])
        for relative in sorted(filter(None, untracked.split("\0"))):
            if time.monotonic() >= deadline:
                raise HarnessError("workspace evidence timed out")
            content = _read_untracked_file(workspace, relative)
            path = workspace / relative
            if content is None:
                if not path.is_symlink():
                    raise HarnessError("non-regular untracked file has no content fingerprint")
                content = str(path.readlink()).encode("utf-8")
            total_bytes += len(relative.encode("utf-8")) + len(content)
            if total_bytes > MAX_DIFF_BYTES:
                raise HarnessError("workspace evidence exceeds the scan limit")
            fingerprint.update(hashlib.sha256(relative.encode("utf-8")).digest())
            fingerprint.update(hashlib.sha256(content).digest())
        if total_bytes > MAX_DIFF_BYTES:
            raise HarnessError("workspace evidence exceeds the scan limit")
        return {"status": "ok", "head": head, "dirty": bool(status), "diff_sha256": fingerprint.hexdigest()}
    except (HarnessError, OSError, RuntimeError, ValueError):
        return unknown
