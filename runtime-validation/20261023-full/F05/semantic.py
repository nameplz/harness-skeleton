from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys

root = Path.cwd()
bot_path = root / "src/orca_discord_bridge/bot.py"
tests_path = root / "tests/test_harness_compatibility.py"
bot_tree = ast.parse(bot_path.read_text())
tests_tree = ast.parse(tests_path.read_text())

def function_nodes(tree: ast.Module, name: str) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]

def policy_call_lines(node: ast.AST) -> list[int]:
    return [call.lineno for call in ast.walk(node) if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "_auth_error"]

bridge = next(node for node in bot_tree.body if isinstance(node, ast.ClassDef) and node.name == "BridgeBot")
on_message = next(node for node in bridge.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "on_message")
policy_lines = policy_call_lines(on_message)
assert policy_lines, "on_message must use the shared _auth_error policy"
content_lines = [call.lineno for call in ast.walk(on_message) if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "codex_input"]
route_lines = [call.lineno for call in ast.walk(on_message) if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "forward_to_codex"]
assert content_lines and min(policy_lines) < min(content_lines), "guild/user policy must run before content processing"
assert route_lines and min(policy_lines) < min(route_lines), "guild/user policy must run before Codex routing"

for name in ("terminals_command", "connect_command", "status_command", "disconnect_command", "terminal_autocomplete", "send_to_codex_context"):
    nodes = function_nodes(bot_tree, name)
    assert nodes and any(policy_call_lines(node) for node in nodes), f"{name} must keep the shared authorization policy"
modal = next(node for node in ast.walk(bot_tree) if isinstance(node, ast.ClassDef) and node.name == "ForwardModal")
submit = next(node for node in modal.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "on_submit")
assert policy_call_lines(submit), "modal submit must keep the shared authorization policy"

spy_test = function_nodes(tests_tree, "test_denied_events_do_not_call_orca")
assert spy_test, "missing denied-event call-spy regression test"
spy_source = ast.get_source_segment(tests_path.read_text(), spy_test[0]) or ""
for required in ("AsyncMock", "assert_not_awaited", "forward_to_codex", "list_terminals", "validate_codex_binding", "get_agent_snapshot", "resolve_binding", "exchange"):
    assert required in spy_source, f"denied-event test must spy on {required}"

command = [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "tests/test_harness_compatibility.py::test_discord_message_boundary",
           "tests/test_harness_compatibility.py::test_application_commands_auth_and_connected_paths",
           "tests/test_harness_compatibility.py::test_denied_events_do_not_call_orca"]
env = dict(os.environ)
env.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"})
result = subprocess.run(command, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(result.stdout, end="")
if result.returncode:
    raise SystemExit(result.returncode)
print("host semantic checks passed: shared authorization seam and denied message/command call spies")
