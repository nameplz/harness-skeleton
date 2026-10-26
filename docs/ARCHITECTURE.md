# Harness architecture

## Boundaries and threat model

Codex owns planning, context, tools, and implementation. Harness supplies local deterministic checks, risk signals, evidence, and diagnostics; it has no separate execution runtime. One implementation writer owns mutable work. Independent reviewers are read-only and assess correctness or changed trust boundaries.

Principle 7: the threat model is **agent mistakes**, not a malicious actor controlling both code and validators. Host permissions enforce filesystem, network, and credential boundaries. Local hooks and same-repository validators are feedback, not a sandbox or trusted remote enforcement.

Principle 8: delivery procedures are the project's choice. Harness completes locally and does not require remote services, branch protection, or publication.

## Components and prevented failures

| Component | Failure prevented |
|---|---|
| `AGENTS.md`, Harness skill | Missing acceptance criteria, premature completion, inconsistent tier procedures |
| `.harness/config.toml` | Guessed toolchains; empty checks reported as passing |
| `scripts/harness.py check` | Unsafe argv/paths, unbounded execution, credential-shaped log disclosure |
| `scripts/harness_risk.py` | Lowered hard T2/T3 signals; unnoticed test weakening |
| Evidence capture | Reusing checks after source/config changes |
| `doctor`, `selftest` | Invalid local setup; regressions in Harness safeguards |
| `.codex/hooks/harness_hook.py` | Destructive command mistakes; omitted quick/full validation |
| Read-only reviewer roles | Missed requirement gaps, regressions, and trust-boundary failures |
| Optional task note, `docs/ADR.md` | Lost continuation state and design rationale |

## Validation and evidence

Profiles are explicit argv arrays executed with `shell=False`. Missing/empty profiles produce non-zero `unconfigured`; bootstrap diagnostics allow setup without calling it success. `configured` means valid non-empty profiles and healthy local structure, hooks, and reviewers; it is not product readiness.

The runner validates paths and commands, rejects inline shell/code and unsafe Git options, uses an environment allowlist with safe Git settings, bounds command/profile time and output, and terminates timed-out POSIX process groups. Redaction covers credential patterns, URL userinfo, JWT, PEM, and email; arbitrary unlabelled secrets remain outside detection.

Checks bind results to HEAD, dirty diff, and applied-config hashes before/after execution. Known-repository evidence errors or changes fail closed. Null identity is unavailable evidence. Fingerprints are bounded and non-atomic; ignored artifacts and changes restored between captures can escape them. Arbitrary test code needs host confinement; detached descendants may outlive timeout cleanup.

## Risk, hooks, and review

Risk inspects the whole working tree since HEAD, which can exceed the staged change. Hard T2/T3 cannot be lowered. N1 raises deleted tests, net assertion loss, or added skip/xfail/only markers to at least T2; review decides whether signals are justified. N2 requires acceptance-to-command/exit/output evidence for T1+.

Stop runs quick; direct commit checks use quick for T0/T1 and full for T2/T3 or unknown/failed risk (N3). Unconfigured profiles allow bootstrap without reporting a pass; `stop_hook_active` prevents recursive blocking. Shell wrappers and indirect commands can evade recognition, so hooks are not authorization boundaries.

T2 requires full plus `reviewer`; T3 adds `security_reviewer`. Findings require `path:line` and a concrete failure scenario; styles, preferences, and hypothetical cases are excluded. Reviews and checks must cover the final source/config identity.

## 4.4 Optional remote integration

CI를 쓰려면 원하는 workflow에서 `python -I scripts/harness.py check --full`을 호출하면 된다.
