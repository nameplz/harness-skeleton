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
REQUIRED_TEST_FILE = "tests/test_orca_parsing.py"
TESTS = [
    "tests/test_orca_parsing.py::test_filter_assistant_output_handles_size_boundaries",
    "tests/test_orca_parsing.py::test_local_markdown_links_with_spaces_and_external_links",
]


def run(command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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

    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    source = output / "source"
    for entry in json.loads(args.manifest.read_text())["files"]:
        data = (args.snapshot / entry["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise SystemExit(f"pinned snapshot hash mismatch: {entry['path']}")
        target = source / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    shutil.copyfile(args.baseline_compat, source / "tests/test_harness_compatibility.py")

    changed = []
    if args.patch:
        changed = sorted(line.split("\t", 2)[2] for line in subprocess.run(
            ["git", "apply", "--numstat", str(args.patch)], check=True, text=True,
            stdout=subprocess.PIPE).stdout.splitlines())
        if not set(changed) <= ALLOWED or REQUIRED_TEST_FILE not in changed:
            raise SystemExit(f"expected changes within {sorted(ALLOWED)} and required test file; got {changed}")
        subprocess.run(["git", "apply", "--check", str(args.patch)], cwd=source, check=True)
        subprocess.run(["git", "apply", str(args.patch)], cwd=source, check=True)

    venv = output / ".venv"
    subprocess.run([str(args.base_venv / "bin/python"), "-m", "venv", "--copies", str(venv)], check=True)
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
    env.update({"PATH": f"{venv}/bin:/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp),
                "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    python = str(venv / "bin/python")
    result = {
        "changed_files": changed,
        "pinned_snapshot_manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "baseline_compatibility_fixture_sha256": hashlib.sha256(args.baseline_compat.read_bytes()).hexdigest(),
        "scope": None if args.patch is None else set(changed) <= ALLOWED and REQUIRED_TEST_FILE in changed,
        "wheel": run([python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                      "--wheel-dir", str(wheelhouse), str(source)], output, env),
    }
    if result["wheel"]["exit_code"]:
        raise SystemExit(result["wheel"]["output"])
    wheel = next(wheelhouse.glob("orca_discord_bridge-0.2.0-*.whl"))
    result["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
    result["install"] = run([python, "-m", "pip", "install", "--no-deps", "--force-reinstall",
                             "--no-index", "--find-links", str(wheelhouse),
                             "orca-discord-bridge==0.2.0"], output, env)
    result["suite"] = run([python, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], source, env)
    result["focused"] = run([python, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", *TESTS], source, env)
    semantic = Path(__file__).with_name("semantic.py").read_text()
    result["semantic"] = run([python, "-I", "-B", "-c", semantic], source, env)
    result["status"] = "pass" if all(result[key]["exit_code"] == 0 for key in ("install", "suite", "focused", "semantic")) and result["scope"] is not False else "fail"
    (output / "grade.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: ({"exit_code": value["exit_code"], "tail": value["output"][-600:]} if isinstance(value, dict) and "exit_code" in value else value)
                      for key, value in result.items()}, indent=2, ensure_ascii=False))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
