# F21 — T13 legacy SQLite migration

F21 used the frozen v2-then-v1 order. v2 passed the unchanged host grader (64 tests and all three migration/privacy checks); its configured T1 self-review passed.

v1 also passed the independent functional host grader (73 tests and all three semantics), but was not accepted. Independent code, test, and security reviews confirmed that checking parent path components before `sqlite3.connect(path)` does not bind SQLite's later pathname open to the checked directory. The available Python standard-library sqlite3 API has no file/directory-descriptor connection interface, so the race remains. The static symlink regression does not cover retargeting during the check/open gap.

The v1 candidate's focused and full pytest commands stopped during collection because its Python 3.13 `_sqlite3` extension could not resolve `_sqlite3_enable_load_extension` from the host `libsqlite3.dylib`; no candidate tests ran. The independent host suite did run. The v1 SessionStart hook exited 125; it was not bypassed, and all protected hook/delivery hashes stayed unchanged. No network, live services, hosted CI, push, publication, or merge occurred.

See [frozen task](task.md), [acceptance](acceptance.json), [freeze record](freeze.json), [v2 run](v2-run.json) / [patch](v2-final.patch) / [grade](v2-grade.json), [v1 run](v1-run.json) / [patch](v1-final.patch) / [grade](v1-grade.json), and [pair results](results.json).
