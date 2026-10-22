# F13 — T08 standard delimiter handling

F13 ran v1 then v2 against the frozen T08 task and prompt. The v1 TUI refused to read the candidate task under /private/tmp before making any edits and explicitly declined requesting an exception. No patch or host patch-grade exists for v1; the failed attempt is preserved and was not retried.

The v2 TUI completed in 4m 51s. The extracted patch is limited to src/orca_discord_bridge/formatting.py and tests/test_harness_compatibility.py. The frozen host grader passed: offline wheel build/install, 66 project tests, all four semantic checks (explicit message gate, context authorization/data boundary, mentions disabled, and delimiter forgery), and exact scope. The TUI reported a successful diff check and two read-only reviewers without findings. Harness quick/risk checks were unavailable because scripts/harness.py is absent.

The v2 result passes its individual frozen host grade, but F13 is not a valid accepted matched pair because v1 was blocked before editing. Both attempts used the pinned snapshot; neither candidate created a commit. The TUI parent was a host process and only tool children were sandboxed. No network, live services, hosted CI, publication, push, or merge occurred. Token use and model turns are unknown.

See the frozen task, freeze/calibration, v1 run, v2 run, host grades, and pair results in this directory.
