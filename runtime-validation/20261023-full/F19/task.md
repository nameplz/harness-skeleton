# Task: handle alternate invalid JSON state files safely

Implement the T01 state-loading behavior for this alternate malformed-input set. Continue treating valid non-object JSON roots (`null`, arrays, strings, numbers, and booleans) as an empty disconnected `BridgeState`. Also treat these invalid byte contents as an empty disconnected state without raising: empty file, whitespace-only bytes, truncated JSON, valid JSON followed by trailing garbage, and invalid UTF-8 bytes. Loading must not rewrite or otherwise alter the invalid file.

Preserve missing-file behavior, valid object deserialization, and connect/disconnect persistence. Extend `test_state_roundtrip_and_malformed_json` or add focused compatibility tests for each malformed byte form and the non-object roots.

Limit changes to exactly `src/orca_discord_bridge/state.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from the checkout and install it offline, run the full project test suite and the focused compatibility test module, then run the frozen host semantic checks for non-object roots, malformed byte variants, unchanged input bytes, missing files, valid object state, and connect/disconnect round trips. Use local temporary files only. No network, live Discord/Orca service, publication, push, or merge. Set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` for every pip command.
