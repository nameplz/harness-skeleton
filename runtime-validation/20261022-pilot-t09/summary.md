# T09 pilot: preserve slash-command behavior

Both workflows passed. The pinned implementation already followed the required route, so neither condition changed product code; each added regression coverage to `test_slash_screen_exception_is_narrow`. v1 added 35 lines and v2 added 41 lines, with both replacing four lines.

The baseline suite had 58 tests. Both candidate suites passed 59 tests, and independent host rebuilds/installations passed the same 59-test suite plus local-fake semantic checks for exactly-once command sends, acknowledgements, `/status`-only screen reads with prompt/decorator filtering, and ordinary prompts using structured status. v1’s focused review passed six cases; its code, test, and security reviews passed. v2 used its T1 self-review route.

The task, fixed prompt, acceptance criteria, patches, result details, and host-grade output are recorded alongside this summary. The TUI did not expose Codex thread/turn IDs or token counts; these remain unknown. The TUI parent was a host process, while only tool children used `harness-eval`. Remote CI was not run.
