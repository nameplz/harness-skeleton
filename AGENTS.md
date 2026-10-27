# Project

{one-line description}

## Commands

- Setup: {setup command}; configure checks using [Harness skill](.agents/skills/harness/SKILL.md#validation-profile-setup) if `doctor` reports `unconfigured`.
- Run: {run command}
- Quick: `python scripts/harness.py check --quick`
- Full: `python scripts/harness.py check --full`
- Commit validation: `python scripts/harness.py gate`
- Install commit gate: `python scripts/harness.py install-gate`
- Diagnostics: `python scripts/harness.py doctor` (`--bootstrap` during setup)
- Risk: `python scripts/harness.py risk`
- Harness regression tests: `python scripts/harness.py selftest`

## Layout

- Read: {project source, tests, and reference paths}
- Write: {implementation and test paths for the task}

## Code style

{snippet: replace with a representative project example}

```python
def is_valid_name(name: str) -> bool:
    return bool(name.strip())
```

## Boundaries

- Always: follow existing code patterns, preserve validation, and report acceptance evidence.
- Ask first: before adding dependencies or changing public contracts, data, or permissions.
- Ask first: never push, create a PR, or merge without a user request.
- Never commit secrets, weaken tests to obtain a pass, or declare unverified work complete.
- Never bypass the commit gate (`--no-verify`), change `core.hooksPath` to evade it, or remove it.

## Validation ladder (local)

| Tier | Minimum classification | Stop gate | Commit gate | Agent duty | Independent review |
|---|---|---|---|---|---|
| T0 | Documentation or typo only | quick when configured | quick | None | None |
| T1 | Ordinary local change | quick | quick | Acceptance evidence | None |
| T2 | Public API, dependencies, cross-module contracts, test weakening, Harness config or instructions | quick | full | Full check + evidence | Read-only review |
| T3 | Hooks, runner/risk scripts, auth/secrets/subprocess/SQL/migrations, user-added `.github/workflows/**` | quick | full | Full check + evidence | Read-only review + security review |

Hard T2/T3 signals cannot be lowered. Commit risk covers the whole working tree since HEAD; failed or unreadable risk selects full. Stop keeps quick. Install the commit gate during setup; it validates the current working tree before commit. Intentional bypasses and forged evidence are outside its guarantee.

For T1+, include a final table: acceptance criterion → evidence (command, exit code, 1–3 key output lines). Mark items without evidence **unverified**. If criteria are missing, write 2–5 before starting. Evidence belongs to the checked HEAD, dirty diff, and configuration; revalidate affected changes. Non-commit completion evidence and independent reviews are agent duties.

## References

- [Harness skill](.agents/skills/harness/SKILL.md): procedures, validation profile setup, and task commits.
- Read [architecture](docs/ARCHITECTURE.md) only when modifying Harness itself.
- Consult [decisions](docs/ADR.md) for decision history.
