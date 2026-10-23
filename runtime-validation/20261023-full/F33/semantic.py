from __future__ import annotations
import ast
from pathlib import Path
import re
import subprocess
import sys

root = Path.cwd()
parser_path = root / "tests/test_orca_parsing.py"
compat_path = root / "tests/test_harness_compatibility.py"
parser_tree = ast.parse(parser_path.read_text(encoding="utf-8"))
compat_tree = ast.parse(compat_path.read_text(encoding="utf-8"))

def function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)

parser_test = function(parser_tree, "test_find_exact_agent_by_worktree_and_pane_key")
data_assignment = next(node for node in parser_test.body
                       if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "data" for t in node.targets))
data = ast.literal_eval(data_assignment.value)
worktrees = data["result"]["worktrees"]
selected_id = "repo::/tmp/wt"
selected_key = "tab-2:leaf-2"
selected = next(w for w in worktrees if w.get("worktreeId") == selected_id)
foreign = [w for w in worktrees if w.get("worktreeId") != selected_id]
parser_source = ast.get_source_segment(parser_path.read_text(encoding="utf-8"), parser_test) or ""
checks = {
    "foreign_same_second_pane": any(a.get("paneKey") == selected_key for w in foreign for a in w.get("agents", [])),
    "selected_wrong_first_pane": any(a.get("paneKey") == "tab-1:leaf-1" for a in selected.get("agents", [])),
    "selected_exact_second_pane": any(a.get("paneKey") == selected_key for a in selected.get("agents", [])),
    "parser_requests_second_pane": 'pane_key="tab-2:leaf-2"' in re.sub(r"\s+", "", parser_source),
}
compat_text = compat_path.read_text(encoding="utf-8")
compat_test = function(compat_tree, "test_real_subprocess_structured_completion")
compat_source = ast.get_source_segment(compat_text, compat_test) or ""
compact = re.sub(r"\s+", "", compat_source)
fake = next(node.value for node in ast.walk(compat_tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and "terminal','show" in node.value and "FAKE_ORCA_STATE" in node.value)
checks.update({
    "compat_selected_second_pane": "TerminalBinding('term','wt','tab-2','leaf-2')" in compact,
    "fake_terminal_binding_second_pane": "tab-2" in fake and "leaf-2" in fake and "tab-2:leaf-2" in fake,
    "structured_exact_messages": "result.text==expected" in compact and "SELECTED_PANE_FINAL" in compat_source,
    "no_terminal_screen_read": "['terminal','read']" in compact,
    "distinct_decoy_and_tool_markers": all(marker in compat_text for marker in (
        "FOREIGN_WORKTREE_MESSAGE", "WRONG_PANE_MESSAGE", "PRIVATE_TOOL_NAME", "PRIVATE_TOOL_INPUT")),
})
failed = [name for name, ok in checks.items() if not ok]
print({"checks": checks, "failed": failed})
if failed:
    raise SystemExit(1)
command = [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "tests/test_orca_parsing.py::test_find_exact_agent_by_worktree_and_pane_key",
           "tests/test_harness_compatibility.py::test_real_subprocess_structured_completion"]
result = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(result.stdout, end="")
if result.returncode:
    raise SystemExit(result.returncode)
print("second-pane host semantics passed")
