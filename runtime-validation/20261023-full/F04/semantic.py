from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import sys

root = Path.cwd()
parser_path = root / "tests/test_orca_parsing.py"
compat_path = root / "tests/test_harness_compatibility.py"
parser_tree = ast.parse(parser_path.read_text())
compat_tree = ast.parse(compat_path.read_text())

def function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)

parser_test = function(parser_tree, "test_find_exact_agent_by_worktree_and_pane_key")
data_assignment = next(node for node in parser_test.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "data" for target in node.targets))
data = ast.literal_eval(data_assignment.value)
worktrees = data["result"]["worktrees"]
assert len(worktrees) >= 2, "parser fixture needs a foreign-worktree decoy"
selected = next(worktree for worktree in worktrees if worktree.get("worktreeId") == "repo::/tmp/wt")
foreign = [worktree for worktree in worktrees if worktree.get("worktreeId") != "repo::/tmp/wt"]
assert any(agent.get("paneKey") == "tab-1:leaf-1" for worktree in foreign for agent in worktree.get("agents", [])), "foreign-worktree decoy must reuse the selected pane"
assert any(agent.get("paneKey") != "tab-1:leaf-1" for agent in selected.get("agents", [])), "selected-worktree fixture needs a wrong-pane decoy"
assert any(agent.get("paneKey") == "tab-1:leaf-1" for agent in selected.get("agents", [])), "selected-worktree fixture needs the exact row"

compat_test = function(compat_tree, "test_real_subprocess_structured_completion")
compat_source = ast.get_source_segment(compat_path.read_text(), compat_test) or ""
compact = re.sub(r"\s+", "", compat_source)
assert "result.text" in compat_source and "expected_messages" in compat_source, "structured-completion test must assert the exact selected messages"
assert "['terminal','read']" in compact, "structured-completion test must assert no terminal screen read"
strings = [node.value for node in ast.walk(compat_tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
assert any("FOREIGN_" in value for value in strings), "fake needs distinct foreign-worktree output"
assert any("WRONG_PANE" in value for value in strings), "fake needs distinct wrong-pane output"
assert any("TOOL_NAME" in value for value in strings) and any("TOOL_INPUT" in value for value in strings), "fake needs tool-name and tool-input markers"

command = [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "tests/test_orca_parsing.py::test_find_exact_agent_by_worktree_and_pane_key",
           "tests/test_harness_compatibility.py::test_real_subprocess_structured_completion"]
env = dict(os.environ)
env.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"})
result = subprocess.run(command, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(result.stdout, end="")
if result.returncode:
    raise SystemExit(result.returncode)
print("host semantic checks passed: exact worktree/pane decoys, exact selected output, no tool details or screen reads")
