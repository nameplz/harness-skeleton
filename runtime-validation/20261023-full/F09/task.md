# Task: preserve useful output while abbreviating verbose content

Keep assistant prose, short useful code, shell commands, and readable local-file links when preparing responses for Discord. Replace unified diff/patch content with the existing compact omission marker, including when the diff is the final content with no trailing blank line. Abbreviate a non-shell fenced block when its body exceeds 2,400 characters or 45 lines. Preserve an oversized shell block as executable guidance. Convert local file links under the worktree to readable relative paths while leaving ordinary HTTPS links unchanged.

Add `test_filter_assistant_output_handles_size_boundaries` and `test_local_markdown_links_with_spaces_and_external_links` to `tests/test_orca_parsing.py`. The first must cover prose, a short code example, an oversized non-shell block, an oversized shell block, and a diff ending the message without a trailing blank line; the second must cover a local path containing spaces and line information plus an unchanged external link.

Changes may touch only `src/orca_discord_bridge/orca.py` and `tests/test_orca_parsing.py`; add both named regression tests. Do not add dependencies or change unrelated behavior.

Acceptance: rebuild and install a wheel offline, run the full project suite, and run the two named regression tests. Use local strings and filesystem paths only; no network or live services. Set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` for every pip command. Do not publish, push, or merge.
