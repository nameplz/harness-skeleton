# Harness architecture

## Boundaries and threat model

The agent owns planning, context, tools, and implementation. Harness supplies deterministic checks, risk signals, evidence, and diagnostics, without a separate execution runtime. One writer owns mutable work; independent reviewers are read-only.

Principle 7: the threat model is **agent mistakes**, not control of both code and validators. Host permissions enforce filesystem, network, and credential boundaries.

When reading untrusted input, do not also grant secret access and external writes such as push. Host permissions must enforce this separation; local validators cannot.

Principle 8: delivery procedures are the project's choice. Local completion needs no remote services or publication.

## Components and prevented failures

| Component | Failure prevented | Assumed model weakness | Removal condition |
|---|---|---|---|
| `AGENTS.md`, Harness skill | Premature completion | Forgets procedures | Host enforces acceptance workflow |
| `.harness/config.toml` | Guessed checks | Invents toolchains | Project supplies explicit validation profiles |
| `scripts/harness.py check` | Unsafe or unbounded validation | Misjudges argv | Host enforces argv/path/runtime limits |
| `scripts/harness_risk.py` | Lowered tiers, weakened tests | Underestimates risk | Host enforces minimum tiers |
| Evidence capture/cache | Stale passes | Reuses old evidence | Host binds checks to workspace identity |
| Git pre-commit gate | Unvalidated commits | Omits checks | Host enforces checks before commits |
| `doctor`, `selftest` | Invalid setup, regressions | Misses drift | Project maintains equivalent diagnostics/tests |
| `scripts/hooks/agent_hook.py` | Destructive mistakes | Omits quick checks | Host warns before destructive commands |
| Read-only reviewers | Requirement/trust-boundary gaps | Shares implementation blind spots | Host supplies independent correctness/security review |
| Task note, `docs/ADR.md` | Lost state/rationale | Loses context | Host preserves durable task/design state |

## Minimum verification

| Contract | Guarantee | Mechanism |
|---|---|---|
| MV-1 | Empty profiles cannot pass validation | check, doctor, gate |
| MV-2 | Commits require tier-appropriate current-tree checks | Git pre-commit |
| MV-3 | Passes bind HEAD, tree, config hashes | Evidence cache |
| MV-4 | Test weakening cannot fall below T2 | Risk routing |
| MV-5 | Control files require T2 or higher | Risk routing |
| MV-6 | Harness safeguards have regression tests | selftest |

Bypasses outside guarantees include `--no-verify`, changing `core.hooksPath`, deleting the gate, forged cache records, and insufficient project tests. Non-commit work relies on agent duties. Bootstrap doctor checks structure without declaring profiles configured. Hooks fail open; they are feedback, not isolation.

## Validation and evidence

Profiles use argv arrays and `shell=False`. The runner applies an environment allowlist, safe Git settings, path/command checks, time/output bounds, process-group cleanup, and credential-pattern redaction. Arbitrary test code and unlabelled secrets require host confinement.

Checks bind before/after HEAD, dirty diff, and applied-config hashes. Evidence errors or changes fail closed; null identity is unavailable. Fingerprints are bounded and non-atomic; ignored files and restored changes can escape them. Detached descendants may outlive cleanup.

## Risk, hooks, and review

Risk covers the working tree since HEAD. Hard T2/T3 cannot be lowered. N1 raises deleted tests, net assertion loss, and skip/xfail/only additions to T2. N2 requires acceptance-to-command/exit/output evidence for T1+.

Stop runs quick when configured; unconfigured profiles permit bootstrap without reporting a pass. `stop_hook_active` prevents recursion. Git pre-commit requires quick for T0/T1 and full for T2/T3 or unknown/failed risk. Shell wrappers can evade agent feedback.

T2 requires full plus `reviewer`; T3 adds `security_reviewer`. Findings need `path:line` and a concrete failure scenario. Checks and reviews cover final source/config identity.

## 4.4 Optional remote integration

CI를 쓰려면 원하는 workflow에서 `python -I scripts/harness.py check --full`을 호출하면 된다.
