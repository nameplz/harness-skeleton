from __future__ import annotations
import json
from pathlib import Path
import tomllib

root = Path.cwd()
project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
readme = (root / "README.md").read_text(encoding="utf-8")
dependencies = project.get("dependencies", [])
checks = {
    "bounded_discord_range": "discord.py>=2.7,<2.8" in dependencies,
    "readme_dependency": "discord.py 2.7.x" in readme and "2.7.1" in readme,
    "python_metadata": project.get("requires-python") == ">=3.11" and "Python 3.11+" in readme,
}
print(json.dumps({"checks": checks, "failed": [name for name, ok in checks.items() if not ok]}, sort_keys=True))
raise SystemExit(0 if all(checks.values()) else 1)
