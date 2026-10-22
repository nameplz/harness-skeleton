# T13 matched pilot pair

Task: migrate bridge state from JSON to private SQLite while preserving the configured path and connect/disconnect behavior. Task, prompt, host grader, semantic checks, and baseline calibration were frozen before either condition. The order was v2 then v1.

| Condition | Candidate workflow | Independent host grade |
|---|---|---|
| v2 | Code/security reviews passed. Offline wheel build/install passed. The TUI suite stopped during collection because its `_sqlite3` extension could not resolve `_sqlite3_enable_load_extension` from `/usr/lib/libsqlite3.dylib`; no tests ran there. | Pass: fresh offline wheel, 70 tests, all three migration/privacy checks; exact two-file scope. |
| v1 | Code, test, and security reviews passed after fixing symlink, invalid field type, and malformed SQLite payload findings. The same SQLite symbol mismatch blocked TUI test collection. A conditional low-severity directory TOCTOU risk was accepted; no candidate commit. | Pass: fresh offline wheel, 69 tests, all three migration/privacy checks; exact two-file scope. |

The baseline passed 58 existing tests but failed all three frozen migration/privacy checks. T13 is pilot pair 11 of 12 (22/24 model runs); condition-order balance is five v1→v2 and six v2→v1. Run T17 v1 then v2 next. The separate full evaluation remains at 0/36 pairs (0/72 runs).

The TUI parent ran on the host; harness-eval applied to tool children only. Host grading ran separately and passed both full suites. The v1 concurrent-directory TOCTOU risk remains documented. Tokens, CI, and OS-level audit were not measured; no external calls or publication occurred.
