from __future__ import annotations

import argparse
import hashlib
from email.parser import Parser
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile


def run(command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    return {"exit_code": result.returncode, "output": result.stdout}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--condition", choices=("baseline", "candidate", "positive-control"), required=True)
    parser.add_argument("--patch", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", required=True)
    args = parser.parse_args()
    if (args.condition == "baseline") != (args.patch is None):
        parser.error("baseline has no patch; candidate and positive-control require --patch")

    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
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

    changed: list[str] = []
    if args.patch:
        parsed = subprocess.run(["git", "apply", "--numstat", str(args.patch)], check=True,
                                text=True, stdout=subprocess.PIPE).stdout
        changed = sorted(line.split("	", 2)[2] for line in parsed.splitlines())
        if changed != ["README.md", "pyproject.toml"]:
            raise SystemExit(f"product scope must be README.md and pyproject.toml only; got {changed}")
        subprocess.run(["git", "apply", "--check", str(args.patch)], cwd=source, check=True)
        subprocess.run(["git", "apply", str(args.patch)], cwd=source, check=True)

    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL"}}
    env.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    semantic = Path(__file__).with_name("semantic.py")
    semantics = run([args.python, "-I", "-B", str(semantic)], source, env)

    wheelhouse = output / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    build = run([args.python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                 "--wheel-dir", str(wheelhouse), str(source)], source, env)
    wheels = list(wheelhouse.glob("orca_discord_bridge-0.2.0-*.whl"))
    build_ok = build["exit_code"] == 0 and len(wheels) == 1
    install = {"exit_code": 1, "output": "wheel build did not produce exactly one wheel"}
    installed_metadata = ""
    if build_ok:
        target = output / "installed"
        install = run([args.python, "-m", "pip", "install", "--no-deps", "--no-index",
                       "--target", str(target), str(wheels[0])], source, env)
        metadata_files = list(target.glob("orca_discord_bridge-0.2.0.dist-info/METADATA"))
        if install["exit_code"] == 0 and len(metadata_files) == 1:
            installed_metadata = metadata_files[0].read_text(encoding="utf-8")

    metadata = Parser().parsestr(installed_metadata) if installed_metadata else Parser().parsestr("")
    metadata_ok = ("Requires-Python" in metadata and metadata["Requires-Python"] == ">=3.11"
                   and any(value.replace(" ", "").lower() == "discord-py<2.8,>=2.7"
                           for value in metadata.get_all("Requires-Dist", [])))
    results = {
        "condition": args.condition,
        "changed_files": changed,
        "snapshot_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "host_grader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "semantic_sha256": hashlib.sha256(semantic.read_bytes()).hexdigest(),
        "semantic": semantics,
        "wheel_build": build,
        "offline_install": install,
        "installed_metadata_matches": metadata_ok,
    }
    good = (semantics["exit_code"] == 0 and build_ok and install["exit_code"] == 0
            and metadata_ok and (args.condition == "baseline" or changed == ["README.md", "pyproject.toml"]))
    if args.condition == "baseline":
        results["status"] = "expected_fail" if not good else "calibration_error"
    else:
        results["status"] = "pass" if good else "fail"
    (output / "grade.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"condition": args.condition, "status": results["status"],
                      "changed_files": changed, "semantic": semantics["output"],
                      "wheel_build_exit": build["exit_code"],
                      "offline_install_exit": install["exit_code"],
                      "installed_metadata_matches": metadata_ok}, indent=2, ensure_ascii=False))
    return 0 if results["status"] in {"pass", "expected_fail"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
