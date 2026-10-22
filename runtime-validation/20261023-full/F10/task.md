# Task: add an authenticated Orca doctor command for stale bindings

Add an authenticated /orca doctor application command that reports whether the saved Orca binding is healthy and gives a clear recovery step when it is missing or stale.

Use the saved terminal handle, worktree ID, and pane key. Reject an unauthorized guild or user before making any Orca request. If any saved binding field is missing, report that the bridge is disconnected and recommend /orca connect without calling Orca. Otherwise validate the saved terminal handle. Compare the live worktree and pane with the saved values; if either changed, report a stale binding, recommend /orca connect, and do not request an agent snapshot for the changed binding. For a matching binding, report its terminal handle, worktree ID, pane key, and structured agent state; use an explicit unknown state if no structured snapshot exists. Orca validation errors must also give actionable reconnect guidance.

Do not expose the configured Discord token, snapshot tool input, prompt, or assistant message. Do not read the terminal screen. Keep the command response private.

Add a focused compatibility test named test_orca_doctor_reports_identity_and_stale_guidance in tests/test_harness_compatibility.py. It must cover the healthy binding, stale pane/worktree state, missing state, authorization before Orca calls, structured status, and sensitive-data non-disclosure.

Limit changes to exactly src/orca_discord_bridge/bot.py and tests/test_harness_compatibility.py. Use only local fakes; no live Discord or Orca service, network, publication, push, or merge. Set PIP_NO_INDEX=1 and PIP_DISABLE_PIP_VERSION_CHECK=1 for every pip command.
