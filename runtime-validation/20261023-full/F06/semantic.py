from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path.cwd()
source_script = root / "start.command"
assert source_script.is_file(), "start.command is missing"
assert source_script.stat().st_mode & 0o111, "start.command must be executable"

def write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)

def run(script: Path, project: Path, path_dir: Path, event_log: Path, ui_log: Path, token: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": str(path_dir), "HOME": str(project), "EVENT_LOG": str(event_log), "UI_LOG": str(ui_log),
           "DISCORD_TOKEN": token, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    return subprocess.run(["/bin/bash", str(script)], cwd=project, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)

with tempfile.TemporaryDirectory(prefix="start-command-host-grade-") as tmp:
    base = Path(tmp)
    missing = base / "missing"
    missing.mkdir()
    script = missing / "start.command"
    shutil.copy2(source_script, script)
    bin_dir = missing / "bin"
    bin_dir.mkdir()
    dirname = Path("/usr/bin/dirname")
    assert dirname.is_file()
    (bin_dir / "dirname").symlink_to(dirname)
    write_executable(bin_dir / "osascript", "#!/bin/bash\nprintf '%s\\n' \"$*\" >>\"$UI_LOG\"\n")
    events, ui = missing / "events.log", missing / "ui.log"
    secret = "TOKEN_SHOULD_NEVER_PRINT_93b2f6"
    result = run(script, missing, bin_dir, events, ui, secret)
    combined = result.stdout + result.stderr + (ui.read_text() if ui.exists() else "")
    assert result.returncode != 0, "missing python3 must stop with failure"
    assert "python" in combined.lower() and ("3.11" in combined or "required" in combined.lower()), "missing-Python guidance must be clear"
    assert secret not in combined, "launcher leaked DISCORD_TOKEN"
    assert not events.exists() and not (missing / ".venv").exists(), "missing Python must stop before install or start"

    project = base / "with-python"
    project.mkdir()
    script = project / "start.command"
    shutil.copy2(source_script, script)
    bin_dir = project / "bin"
    bin_dir.mkdir()
    (bin_dir / "dirname").symlink_to(dirname)
    write_executable(bin_dir / "python3", '''#!/bin/bash
printf 'python3 %s\\n' "$*" >>"$EVENT_LOG"
if [[ "$1" == "--version" ]]; then printf 'Python 3.13.0\\n'; exit 0; fi
if [[ "$1" == "-c" ]]; then printf '3.13.0\\n'; exit 0; fi
if [[ "$1" == "-m" && "$2" == "venv" ]]; then
  /bin/mkdir -p "$3/bin"
  /bin/cat >"$3/bin/python" <<'PY_STUB'
#!/bin/bash
printf 'venv %s\\n' "$*" >>"$EVENT_LOG"
exit 0
PY_STUB
  /bin/chmod 755 "$3/bin/python"
fi
exit 0
''')
    events, ui = project / "events.log", project / "ui.log"
    result = run(script, project, bin_dir, events, ui, secret)
    assert result.returncode == 0, f"first launch failed: {result.stderr}"
    combined = result.stdout + result.stderr
    assert secret not in combined, "launcher leaked DISCORD_TOKEN"
    log = events.read_text()
    assert "-m venv" in log, "first launch must create .venv"
    assert "-m pip" in log and "-m orca_discord_bridge" in log, "venv must install and start the module"
    events.unlink()

    # An existing local interpreter must work even with no system python3 on PATH.
    reuse_bin = project / "reuse-bin"
    reuse_bin.mkdir()
    (reuse_bin / "dirname").symlink_to(dirname)
    result = run(script, project, reuse_bin, events, ui, secret)
    assert result.returncode == 0, f"existing venv should start without system Python: {result.stderr}"
    combined = result.stdout + result.stderr
    assert secret not in combined, "launcher leaked DISCORD_TOKEN"
    log = events.read_text()
    assert "-m venv" not in log, "repeated launch must reuse .venv"
    assert "-m pip" in log and "-m orca_discord_bridge" in log, "reused venv must install and start the module"

command = [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "tests/test_harness_compatibility.py::test_start_command_missing_python_bootstrap"]
env = dict(os.environ)
env.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"})
result = subprocess.run(command, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(result.stdout, end="")
if result.returncode:
    raise SystemExit(result.returncode)
print("host semantic checks passed: missing-Python guidance, token redaction, venv create/reuse, install and module start")
