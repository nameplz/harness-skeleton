from pathlib import Path
from urllib.parse import quote
from orca_discord_bridge.orca import _filter_assistant_output

root = Path.home() / "repo with spaces"
text = (
    "Intro prose.\n\n```toml\nmode = 'safe'\n```\n\n"
    "```bash\necho keep-shell-command\n" + "echo long-shell-command\n" * 100 + "```\n\n"
    "[absolute](/" + str(root).lstrip("/") + "/docs/index.md:20)\n"
    "[tilde](~/repo with spaces/README.md)\n"
    "[tilde-line](~/repo with spaces/docs/guide.md:7)\n"
    "[file](file://" + quote(str(root / "docs" / "start here.md"), safe="/") + ")\n"
    "[web](https://example.com/docs)\n\n"
    "Inline literal: `[literal](/" + str(root).lstrip("/") + "/README.md)`\n"
    "[outside](/private/eval-secret-path.txt)\n\n"
    "diff --git a/a.py b/a.py\nindex 1..2\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n"
    "-old-diff-marker\n+new-diff-marker\n\n"
    "````diff --git a/a.py b/a.py\nFENCED_DIFF_BODY_MARKER\n````\n\n"
    "```bash -lc\necho keep-shell-option\n" + "echo long-shell-option\n" * 100 + "```\n\n"
    "```python\nLARGE_NON_SHELL_MARKER_" + "x" * 2600 + "\n```\n\nOutro prose."
)
result = _filter_assistant_output(text, str(root))
checks = {
    "prose": "Intro prose." in result and "Outro prose." in result,
    "short_code": "mode = 'safe'" in result,
    "shell": "keep-shell-command" in result and "long-shell-command" in result,
    "absolute_link": "docs/index.md:20" in result,
    "tilde_link": "README.md" in result,
    "tilde_line_suffix": "docs/guide.md:7" in result,
    "file_uri": "start here.md" in result,
    "web_link": "https://example.com/docs" in result,
    "inline_code_literal": "`[literal](/" + str(root).lstrip("/") + "/README.md)`" in result,
    "outside_path_hidden": "/private/eval-secret-path.txt" not in result and "outside" in result,
    "diff_abbreviated": all(x not in result for x in ("old-diff-marker", "new-diff-marker", "diff --git")),
    "long_fence_diff_abbreviated": "FENCED_DIFF_BODY_MARKER" not in result,
    "shell_options_preserved": "keep-shell-option" in result and "long-shell-option" in result,
    "large_non_shell_abbreviated": "LARGE_NON_SHELL_MARKER_" not in result,
    "diff_notice": "diff/patch" in result or "생략" in result,
    "large_block_notice": "긴 코드" in result or "omitted" in result.lower() or "abbrevi" in result.lower(),
}
failed = [name for name, passed in checks.items() if not passed]
print({"checks": checks, "failed": failed})
raise SystemExit(bool(failed))
