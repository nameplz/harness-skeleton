from __future__ import annotations

from orca_discord_bridge.orca import _filter_assistant_output


long_code = "```python\nCODE_SENTINEL_" + "x" * 2_500 + "\n```"
long_shell_body = "echo SHELL_SENTINEL_" + "y" * 2_500
long_shell = f"```bash\n{long_shell_body}\n```"
diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-secret\n+changed"
short_code = "```python\nprint('hello')\n```"
text = "Useful explanation.\n\n" + short_code + "\n\n" + long_code + "\n\n" + long_shell + "\n\n" + diff
filtered = _filter_assistant_output(text)
assert "Useful explanation." in filtered
assert "print('hello')" in filtered
assert "CODE_SENTINEL_" not in filtered
assert "_(긴 코드 블록 생략)_" in filtered
assert long_shell_body in filtered
assert filtered.endswith("_(diff/patch 상세 생략)_")
assert "diff --git" not in filtered

root = "/Users/me/project with spaces"
linked = _filter_assistant_output(
    "[phase report](/Users/me/project with spaces/docs/phase 6.md:20) "
    "[website](https://example.com/docs)",
    root,
)
assert linked == "phase report (`docs/phase 6.md:20`) [website](https://example.com/docs)"

print("host semantic checks passed: prose, short code, shell preservation, diff/large-code omission, local relative path with spaces, and unchanged HTTPS link")
