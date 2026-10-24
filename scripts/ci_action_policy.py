"""GitHub Actions reference and local-action security checks."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Callable

FULL_SHA_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}")
DOCKER_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z", re.IGNORECASE)


def check_job_actions(relative: Path, job: dict[str, Any], root: Path, *,
                      parse_workflow_yaml: Callable[[str], dict[str, Any]],
                      max_workflow_bytes: int) -> list[str]:
    errors: list[str] = []
    if "uses" in job:
        workflow_ref = job["uses"]
        if not isinstance(workflow_ref, str):
            errors.append(f"{relative}: reusable workflow reference must be a string")
        elif workflow_ref.startswith("./"):
            if not _is_safe_local_workflow_reference(workflow_ref, root):
                errors.append(
                    f"{relative}: local reusable workflow target must exist as a .yml or .yaml file "
                    "under .github/workflows/"
                )
            else:
                target_path = root / workflow_ref[2:]
                try:
                    if target_path.stat().st_size > max_workflow_bytes:
                        raise ValueError("workflow exceeds the size limit")
                    target = parse_workflow_yaml(target_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
                    errors.append(f"{relative}: local reusable workflow target is invalid or too large")
                else:
                    if not _has_workflow_call(target.get("on")):
                        errors.append(f"{relative}: local reusable workflow target must declare workflow_call")
        elif not _is_pinned_external_workflow_reference(workflow_ref):
            errors.append(
                f"{relative}: external reusable workflow must be pinned to a full commit SHA "
                "and reference .github/workflows/*.yml or *.yaml"
            )
    errors.extend(_check_action_steps(relative, job.get("steps", []), root))
    return errors


def check_local_action_metadata(root: Path, pr_action_refs: list[str], *,
                                parse_workflow_yaml: Callable[[str], dict[str, Any]],
                                check_expressions: Callable[[Path, str, dict[str, Any]], list[str]],
                                max_actions: int, max_file_bytes: int) -> list[str]:
    actions_root = root / ".github/actions"
    if actions_root.is_symlink():
        return [".github/actions cannot be a symlink"]
    if not actions_root.exists():
        return []
    if not actions_root.is_dir():
        return [".github/actions must be a directory"]
    try:
        paths = sorted(path for path in actions_root.rglob("*")
                       if path.name.casefold() in {"action.yml", "action.yaml"})
    except (OSError, RuntimeError):
        return [".github/actions metadata could not be inspected"]
    if len(paths) > max_actions:
        return [".github/actions metadata count exceeds the limit"]
    errors: list[str] = []
    actions_by_ref: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in paths:
        relative = path.relative_to(root)
        try:
            if path.is_symlink():
                errors.append(f"{relative} cannot be a symlink")
                continue
            path.resolve(strict=True).relative_to(root)
            if path.stat().st_size > max_file_bytes:
                errors.append(f"{relative} exceeds the action metadata size limit")
                continue
            action = parse_workflow_yaml(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, RuntimeError, ValueError, subprocess.SubprocessError):
            errors.append(f"{relative}: action metadata YAML or file path is invalid")
            continue
        actions_by_ref[f"./{relative.parent.as_posix()}"] = (relative, action)
        runs = action.get("runs")
        if isinstance(runs, dict) and runs.get("using") == "composite":
            steps = runs.get("steps")
            if not isinstance(steps, list):
                errors.append(f"{relative}: composite action steps must be a list")
            else:
                errors.extend(_check_action_steps(relative, steps, root))
        elif isinstance(runs, dict) and runs.get("using") == "docker":
            errors.extend(_check_docker_action(relative, path.parent, runs, root, max_file_bytes))
    errors.extend(_check_pr_action_expressions(pr_action_refs, actions_by_ref, check_expressions))
    return errors


def _check_pr_action_expressions(pr_action_refs: list[str],
                                 actions_by_ref: dict[str, tuple[Path, dict[str, Any]]],
                                 check_expressions: Callable[[Path, str, dict[str, Any]], list[str]]) -> list[str]:
    errors: list[str] = []
    pending = list(pr_action_refs)
    inspected: set[str] = set()
    while pending:
        action_ref = pending.pop()
        if action_ref in inspected:
            continue
        inspected.add(action_ref)
        metadata = actions_by_ref.get(action_ref)
        if metadata is None:
            errors.append(f"{action_ref}: local action metadata is missing")
            continue
        relative, action = metadata
        errors.extend(check_expressions(relative, "local action", action))
        runs = action.get("runs")
        steps = runs.get("steps") if isinstance(runs, dict) and runs.get("using") == "composite" else None
        if isinstance(steps, list):
            if _contains_github_environment_file(action):
                errors.append(f"{relative}: PR composite actions cannot change GitHub environment or path files")
            if any(
                isinstance(step, dict) and "continue-on-error" in step
                and not _is_explicit_false(step["continue-on-error"])
                for step in steps
            ):
                errors.append(f"{relative}: PR composite action steps cannot ignore failures")
            pending.extend(step["uses"] for step in steps if isinstance(step, dict)
                           and isinstance(step.get("uses"), str)
                           and (step["uses"] == "./.github/actions"
                                or step["uses"].startswith("./.github/actions/")))
    return errors


def _contains_github_environment_file(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_github_environment_file(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_github_environment_file(item) for item in value)
    return isinstance(value, str) and re.search(r"\bGITHUB_", value, re.IGNORECASE) is not None


def _check_action_steps(relative: Path, steps: Any, root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(steps, list):
        return errors
    for step in steps:
        if not isinstance(step, dict) or "uses" not in step:
            continue
        action_ref = step["uses"]
        if not isinstance(action_ref, str):
            errors.append(f"{relative}: action reference must be a string")
        elif action_ref.startswith("./"):
            if not _is_safe_local_action_reference(action_ref, root):
                errors.append(f"{relative}: local action path must stay under .github/actions/")
        elif action_ref.startswith("docker://"):
            if not DOCKER_DIGEST_RE.fullmatch(action_ref.removeprefix("docker://")):
                errors.append(f"{relative}: Docker action image must be pinned by SHA-256 digest")
        elif not FULL_SHA_RE.fullmatch(action_ref):
            errors.append(f"{relative}: external action must be pinned to a full commit SHA: {action_ref}")
        if isinstance(action_ref, str) and _is_checkout_action(action_ref):
            errors.extend(_check_checkout_credentials(relative, step))
    return errors


def _check_docker_action(relative: Path, action_root: Path, runs: dict[str, Any], root: Path,
                         max_file_bytes: int) -> list[str]:
    image = runs.get("image")
    if not isinstance(image, str) or not image:
        return [f"{relative}: Docker action image must be a digest-pinned Docker image or local Dockerfile"]
    if image.startswith("docker://"):
        remote_image = image.removeprefix("docker://")
        return [] if DOCKER_DIGEST_RE.fullmatch(remote_image) else [
            f"{relative}: Docker action image must be pinned by SHA-256 digest"
        ]
    image_path = Path(image)
    if image_path.is_absolute() or chr(92) in image or any(part in {"", ".", ".."} for part in image_path.parts):
        return [f"{relative}: Dockerfile path must stay within the local action directory"]
    dockerfile = action_root / image_path
    try:
        current = action_root
        for part in image_path.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError
        resolved_root = action_root.resolve(strict=True)
        resolved_file = dockerfile.resolve(strict=True)
        resolved_root.relative_to(root.resolve(strict=True))
        resolved_file.relative_to(resolved_root)
        if not resolved_file.is_file() or resolved_file.stat().st_size > max_file_bytes:
            raise ValueError
        lines = _logical_dockerfile_instructions(resolved_file.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeError, RuntimeError, ValueError):
        return [f"{relative}: Dockerfile path is invalid or outside the local action directory"]
    return _check_dockerfile(relative, lines)


def _check_dockerfile(relative: Path, lines: list[str]) -> list[str]:
    aliases: set[str] = set()
    stage_count = 0
    for stripped in lines:
        fields = stripped.split()
        instruction = fields[0].casefold()
        add_sources = fields[1:-1]
        if instruction == "add" and any(
            "$" in source or re.match(r"(?:https?://|git@|(?:ssh|git)://)", source, re.IGNORECASE)
            for source in add_sources
        ):
            return [f"{relative}: Dockerfile cannot fetch remote sources with ADD"]
        # shortcut: catch common download tools; review Dockerfile RUN changes for other network access.
        if instruction == "run" and ("$" in stripped or "<<" in stripped or re.search(
            r"\b(?:curl|wget|fetch|aria2c|git\s+clone|apt(?:-get)?|apk\s+add|yum|dnf|"
            r"pip(?:\d+(?:\.\d+)?)?\s+install|npm\s+(?:i|install|ci|add|update)|"
            r"yarn(?:\s+(?:install|add|upgrade))?|pnpm(?:\s+(?:install|i|add|update))?|"
            r"bun\s+(?:install|i|add|update)|"
            r"urlopen|urlretrieve|urllib(?:\.request)?|requests?\.(?:get|post|put|delete)|"
            r"socket|create_connection|connect_ex)\b",
            stripped, re.IGNORECASE,
        )):
            return [f"{relative}: Dockerfile RUN cannot fetch mutable remote code"]
        if instruction == "copy":
            from_match = re.search(r"(?:^|\s)--from(?:=|\s+)([^\s]+)", stripped, re.IGNORECASE)
            from_value = from_match.group(1) if from_match else None
            if from_value is not None and from_value.casefold() not in aliases and not (
                from_value.isdecimal() and int(from_value) < stage_count
            ) and not DOCKER_DIGEST_RE.fullmatch(from_value):
                return [f"{relative}: Dockerfile external COPY --from images must be pinned by SHA-256 digest"]
        if instruction == "from" and len(fields) >= 2:
            fields = fields[1:]
            while fields and fields[0].startswith("--"):
                fields = fields[1:]
            if fields:
                image_name = fields[0]
                is_previous_stage = image_name.casefold() in aliases or (
                    image_name.isdecimal() and int(image_name) < stage_count
                )
                if image_name.casefold() != "scratch" and not is_previous_stage \
                        and not DOCKER_DIGEST_RE.fullmatch(image_name):
                    return [f"{relative}: Dockerfile base images must be pinned by SHA-256 digest"]
                if len(fields) >= 3 and fields[1].casefold() == "as":
                    aliases.add(fields[2].casefold())
                stage_count += 1
    if stage_count == 0:
        return [f"{relative}: Dockerfile base images must be pinned by SHA-256 digest"]
    return []


def _logical_dockerfile_instructions(lines: list[str]) -> list[str]:
    escape_char = "\\"
    for line in lines[:5]:
        match = re.match(r"\s*#\s*escape\s*=\s*([\x60\\])\s*$", line, re.IGNORECASE)
        if match:
            escape_char = match.group(1)
            break
    instructions: list[str] = []
    pending = ""
    for line in lines:
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        combined = f"{pending} {stripped}".strip()
        if combined.endswith(escape_char):
            pending = combined[:-1].rstrip()
            continue
        instructions.append(combined)
        pending = ""
    if pending:
        instructions.append(pending)
    return instructions


def _is_safe_local_workflow_reference(workflow_ref: str, root: Path) -> bool:
    if chr(92) in workflow_ref or not workflow_ref.startswith("./.github/workflows/"):
        return False
    parts = workflow_ref[2:].split("/")
    if (
        any(part in {"", ".", ".."} or any(ord(char) < 32 or ord(char) == 127 for char in part)
            for part in parts)
        or Path(parts[-1]).suffix.casefold() not in {".yml", ".yaml"}
    ):
        return False
    workspace = root.resolve(strict=True)
    workflow_root = (workspace / ".github/workflows").resolve(strict=False)
    target_path = workspace / workflow_ref[2:]
    target = target_path.resolve(strict=False)
    try:
        workflow_root.relative_to(workspace)
        target.relative_to(workflow_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return (
        target_path.is_file()
        and not any((workspace / ".github/workflows" / part).is_symlink() for part in parts[2:])
    )


def _is_pinned_external_workflow_reference(workflow_ref: str) -> bool:
    path, separator, sha = workflow_ref.rpartition("@")
    parts = path.split("/")
    return (
        bool(separator)
        and re.fullmatch(r"[0-9a-f]{40}", sha) is not None
        and len(parts) >= 5
        and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts[:2])
        and parts[2:4] == [".github", "workflows"]
        and all(part not in {"", ".", ".."} and "\\" not in part
                and not any(ord(char) < 32 or ord(char) == 127 for char in part) for part in parts[4:])
        and Path(parts[-1]).suffix.casefold() in {".yml", ".yaml"}
    )


def _has_workflow_call(triggers: Any) -> bool:
    return (
        isinstance(triggers, dict) and "workflow_call" in triggers
        or isinstance(triggers, str) and triggers == "workflow_call"
        or isinstance(triggers, list) and "workflow_call" in triggers
    )


def _is_explicit_false(value: Any) -> bool:
    return value is False or isinstance(value, str) and value.strip().casefold() == "false"


def _is_safe_local_action_reference(action_ref: str, root: Path) -> bool:
    if chr(92) in action_ref or not (
        action_ref == "./.github/actions" or action_ref.startswith("./.github/actions/")
    ):
        return False
    parts = action_ref[2:].split("/")
    if any(part in {"", ".", ".."} or any(ord(char) < 32 or ord(char) == 127 for char in part)
           for part in parts):
        return False
    workspace = root.resolve(strict=True)
    actions_root = (workspace / ".github/actions").resolve(strict=False)
    target = (workspace / action_ref[2:]).resolve(strict=False)
    try:
        actions_root.relative_to(workspace)
        target.relative_to(actions_root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return not any((workspace / ".github/actions" / part).is_symlink() for part in parts[2:])


def _is_checkout_action(action_ref: str) -> bool:
    return action_ref.rsplit("@", 1)[0].casefold() == "actions/checkout"


def _check_checkout_credentials(relative: Path, step: dict[str, Any]) -> list[str]:
    options = step.get("with")
    if not isinstance(options, dict):
        return [f"{relative}: actions/checkout must set persist-credentials: false"]
    normalized = {str(key).casefold(): value for key, value in options.items()}
    if len(normalized) != len(options) or normalized.get("persist-credentials") is not False:
        return [f"{relative}: actions/checkout must set persist-credentials: false"]
    if set(normalized) & {"token", "ssh-key", "ssh-token"}:
        return [f"{relative}: custom checkout credentials are forbidden"]
    clean = normalized.get("clean", True)
    if not (clean is True or isinstance(clean, str) and clean.casefold() == "true"):
        return [f"{relative}: checkout must keep workspace cleaning enabled"]
    if set(normalized) & {
        "repository", "ref", "path", "sparse-checkout", "sparse-checkout-cone-mode", "filter",
        "github-server-url", "allow-unsafe-pr-checkout",
    }:
        return [f"{relative}: checkout must use the current pull request repository, revision, and full root"]
    return []
