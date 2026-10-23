from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ALLOWED = {
    "src/orca_discord_bridge/orca.py",
    "tests/test_orca_parsing.py",
}


def run(command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {"exit_code": result.returncode, "output": result.stdout}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--base-venv", type=Path, required=True)
    parser.add_argument("--condition", choices=("baseline", "candidate", "positive-control"), required=True)
    parser.add_argument("--patch", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (args.condition == "baseline") != (args.patch is None):
        parser.error("baseline has no patch; candidate and positive-control require --patch")

    manifest = json.loads(args.manifest.read_text())
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    source = output / "source"
    for entry in manifest["files"]:
        src = args.snapshot / entry["path"]
        data = src.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise SystemExit(f"pinned snapshot hash mismatch: {entry['path']}")
        dst = source / entry["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    changed = []
    if args.patch:
        parsed = subprocess.run(["git", "apply", "--numstat", str(args.patch)], check=True, text=True, stdout=subprocess.PIPE).stdout
        changed = sorted(line.split("\t", 2)[2] for line in parsed.splitlines())
        if set(changed) - ALLOWED:
            raise SystemExit(f"out-of-scope paths: {set(changed) - ALLOWED}")
        subprocess.run(["git", "apply", "--unidiff-zero", "--check", str(args.patch)], cwd=source, check=True)
        subprocess.run(["git", "apply", "--unidiff-zero", str(args.patch)], cwd=source, check=True)

    venv = output / ".venv"
    subprocess.run([str(args.base_venv / "bin/python"), "-m", "venv", "--copies", str(venv)], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
    home.mkdir()
    temp.mkdir()
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
        "condition": args.condition,
        "changed_files": changed,
        "snapshot_manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "host_grader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    results["wheel"] = run([python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheelhouse), str(source)], output, env)
    if results["wheel"]["exit_code"] == 0:
        wheel = next(wheelhouse.glob("orca_discord_bridge-0.2.0-*.whl"))
        results["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
        results["install"] = run([python, "-m", "pip", "install", "--no-deps", "--force-reinstall", "--no-index", "--find-links", str(wheelhouse), "orca-discord-bridge==0.2.0"], output, env)
        results["suite"] = run([python, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], source, env)
        semantic = Path(__file__).with_name("semantic.py").read_text()
        results["semantic"] = run([python, "-I", "-B", "-c", semantic], source, env)
    else:
        results.update({name: {"exit_code": 125, "output": "skipped after wheel build failure"} for name in ("install", "suite", "semantic")})

    good = all(results[name]["exit_code"] == 0 for name in ("wheel", "install", "suite", "semantic"))
    if args.condition == "baseline":
        calibrated = results["wheel"]["exit_code"] == 0 and results["install"]["exit_code"] == 0 and results["suite"]["exit_code"] == 0 and results["semantic"]["exit_code"] != 0
        results["status"] = "expected_fail" if calibrated else "calibration_error"
    else:
        results["status"] = "pass" if good else "fail"
    (output / "grade.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        "condition": args.condition,
        "status": results["status"],
        "changed_files": changed,
        "wheel": results["wheel"]["exit_code"],
        "install": results["install"]["exit_code"],
        "suite_tail": results["suite"]["output"][-300:],
        "semantic": results["semantic"]["output"][-900:],
        "wheel_sha256": results.get("wheel_sha256"),
    }, indent=2, ensure_ascii=False))
    return 0 if results["status"] in {"pass", "expected_fail"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
