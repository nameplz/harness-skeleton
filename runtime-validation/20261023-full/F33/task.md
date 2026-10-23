# Task: keep structured replies bound to a second pane

Extend the worktree/pane isolation regression tests so structured assistant output is selected from a non-first pane. The selected terminal is in worktree repo::/tmp/wt with paneKey tab-2:leaf-2. Put a foreign-worktree agent using that same pane key before the selected worktree, and a tab-1:leaf-1 agent in the selected worktree as a wrong-pane decoy. Assert that only the exact second-pane row is returned.

In the compatibility fake, make terminal/show bind tab-2 and leaf-2, make its structured agent snapshots use tab-2:leaf-2, and keep separate foreign-worktree, wrong-pane, and tool-detail markers. Assert the structured completion contains only selected-pane messages and never reads the terminal screen.

Limit changes to tests/test_orca_parsing.py and tests/test_harness_compatibility.py. Do not change runtime behavior, application commands, authorization, or output formatting.

Acceptance: rebuild/install a clean wheel offline and run the full project suite using the exact commands in AGENTS.md/TASK.md. Use synthetic local worktree snapshots and fake subprocesses only. Set PIP_NO_INDEX=1 and PIP_DISABLE_PIP_VERSION_CHECK=1 on every pip command. Do not access the network or live services, publish, push, or merge. Stop at the fixed 30-minute condition cap.
