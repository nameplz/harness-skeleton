# Harness agent guide

## Commands

- `python scripts/harness.py check --quick`
- `python scripts/harness.py check --full`
- `python scripts/harness.py risk`
- `python scripts/harness.py doctor`
- `python scripts/harness.py selftest`

## Validation ladder (local)

| Tier | Minimum classification | Stop gate | Commit gate | Agent duty | Independent review |
|---|---|---|---|---|---|
| T0 | Documentation or typo only | quick when configured | quick | None | None |
| T1 | Ordinary local change | quick | quick | Acceptance evidence | None |
| T2 | Public API, dependencies, cross-module contracts, test weakening, `.harness/config.toml` | quick | full | Full check + evidence | `reviewer` |
| T3 | Hooks, runner/risk scripts, auth/secrets/subprocess/SQL/migrations, user-added `.github/workflows/**` | quick | full | Full check + evidence | `reviewer` + `security_reviewer` |

Hard T2/T3 signals cannot be lowered. Commit risk covers the whole working tree since HEAD; failed or unreadable risk selects full. Stop keeps quick.

## Completion evidence (N2)

For T1+, include a final table: acceptance criterion → evidence (command, exit code, 1–3 key output lines). Mark items without evidence **unverified**. If criteria are missing, write 2–5 before starting. Evidence belongs to the checked HEAD, dirty diff, and configuration; revalidate affected changes.

## Rules and references

- Never weaken tests to obtain a pass or declare unverified work complete.
- Never push, create a PR, or merge without a user request.
- Follow [Harness skill](.agents/skills/harness/SKILL.md) for procedures and task commits.
- If `doctor` reports `unconfigured`, follow the Harness skill's **Validation profile setup / 검증 프로필 설정** section.
- Read [architecture](docs/ARCHITECTURE.md) only when modifying Harness itself; consult [decisions](docs/ADR.md) for decision history.
