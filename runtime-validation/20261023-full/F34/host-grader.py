from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ALLOWED = {
    "src/orca_discord_bridge/state.py",
    "tests/test_harness_compatibility.py",
}


def run(name: str, command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {"exit_code": result.returncode, "output": result.stdout}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline-compat", type=Path, required=True)
    parser.add_argument("--base-venv", type=Path, required=True)
    parser.add_argument("--condition", choices=("baseline", "v1", "v2"), required=True)
    parser.add_argument("--patch", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (args.condition == "baseline") != (args.patch is None):
        parser.error("baseline has no patch; v1/v2 require --patch")

    manifest = json.loads(args.manifest.read_text())
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    source = output / "source"
    for entry in manifest["files"]:
        src = args.snapshot / entry["path"]
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            raise SystemExit(f"pinned snapshot hash mismatch: {entry['path']}")
        dst = source / entry["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    compat = source / "tests/test_harness_compatibility.py"
    shutil.copyfile(args.baseline_compat, compat)

    changed = []
    if args.patch:
        parsed = subprocess.run(["git", "apply", "--numstat", str(args.patch)], check=True, text=True, stdout=subprocess.PIPE).stdout
        changed = sorted(line.split("\t", 2)[2] for line in parsed.splitlines())
        if set(changed) - ALLOWED:
            raise SystemExit(f"out-of-scope paths: {set(changed) - ALLOWED}")
        subprocess.run(["git", "apply", "--check", str(args.patch)], cwd=source, check=True)
        subprocess.run(["git", "apply", str(args.patch)], cwd=source, check=True)

    venv = output / ".venv"
    base_python = args.base_venv / "bin/python"
    subprocess.run([str(base_python), "-m", "venv", "--copies", str(venv)], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    site = venv / "lib/python3.13/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for item in (args.base_venv / "lib/python3.13/site-packages").iterdir():
        if item.name.lower().replace("-", "_").replace(".", "_").startswith("orca_discord_bridge"):
            continue
        target = site / item.name
        if item.is_dir():
            shutil.copytree(item, target, symlinks=False, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target, follow_symlinks=True)
    if any(path.is_symlink() for path in venv.rglob("*")):
        raise SystemExit("copied host venv unexpectedly contains a symlink")

    wheelhouse = output / "wheelhouse"
    wheelhouse.mkdir()
    home, temp = output / "home", output / "tmp"
    home.mkdir(); temp.mkdir()
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL"}}
    env.update({
        "PATH": f"{venv}/bin:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temp),
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    python = str(venv / "bin/python")
    results = {
        "changed_files": changed,
        "pinned_snapshot_manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "baseline_compatibility_fixture_sha256": hashlib.sha256(args.baseline_compat.read_bytes()).hexdigest(),
    }
    results["wheel"] = run("wheel", [python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheelhouse), str(source)], output, env)
    if results["wheel"]["exit_code"]:
        raise SystemExit(results["wheel"]["output"])
    wheel = next(wheelhouse.glob("orca_discord_bridge-0.2.0-*.whl"))
    results["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
    results["install"] = run("install", [python, "-m", "pip", "install", "--no-deps", "--force-reinstall", "--no-index", "--find-links", str(wheelhouse), "orca-discord-bridge==0.2.0"], output, env)
    results["suite"] = run("suite", [python, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], source, env)
    semantic_code = Path(__file__).with_name("semantic.py").read_text()
    results["semantic"] = run("semantic", [python, "-I", "-B", "-c", semantic_code], source, env)
    results["status"] = "pass" if all(results[key]["exit_code"] == 0 for key in ("install", "suite", "semantic")) else "fail"
    (output / "grade.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: ({"exit_code": value["exit_code"], "tail": value["output"][-500:]} if isinstance(value, dict) and "exit_code" in value else value) for key, value in results.items()}, indent=2, ensure_ascii=False))
    return 0 if results["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
