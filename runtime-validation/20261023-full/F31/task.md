# Task: correct quickstart and operational documentation

Update only `README.md` in the pinned Orca Discord Bridge snapshot. Keep its existing Korean style and make setup and operational guidance accurate against the source.

Document the supported Python and Orca/Codex prerequisites, an executable installation and launch path, all required and optional environment variables with defaults and path/timeout behavior, the structured agent-row response flow and its limits, the actual guild/user/channel authorization scope, the lack of GitHub API or webhook receiver, and Discord's slash-command mapping including the narrow `/status` screen-read exception. Do not claim that `start.command` exists or that the bridge supplies an OS/VM sandbox or other unsupported security guarantees.

Do not change runtime code, tests, dependencies, or other documentation. Do not use network or live Discord/Orca services, push, publish, or merge. Run `git diff --check -- README.md`; no project tests are required for this documentation-only task. Report the checks and any unavailable Harness commands.
