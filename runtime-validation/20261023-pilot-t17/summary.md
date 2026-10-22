# T17 matched pilot pair

Task: add one minimal GitHub Actions workflow for push and pull request, Python 3.11–3.13, immutable action pins, least-privilege permissions, and offline local validation. Task, prompt, grader, semantic checks, model, condition order, and 30-minute cap were frozen before either condition. Order: v1 then v2.

| Condition | Candidate outcome | Independent host grade |
|---|---|---|
| v1 | 5m53s TUI-reported. Build/install and 58 tests passed; code, test, and security reviews passed. Local feature-branch creation was denied, so no commit was made. | Pass: fresh offline wheel, 58 tests, all frozen YAML/security checks, exact one-file scope. |
| v2 | 3m00s TUI-reported. Build/install, 58 tests, code and security reviews passed. The snapshot lacks `scripts/harness.py` and `.harness/config.toml`, so Harness risk/full checks were unavailable. Two initial read-only pip diagnostics ran without the required offline variables; the candidate reported no index access. | Pass: fresh offline wheel, 58 tests, all frozen YAML/security checks, exact one-file scope. |

Both patches add only `.github/workflows/ci.yml`; no GitHub workflow was dispatched. The actual hosted CI result remains unmeasured. Token usage and shell-command counts were not captured. The v2 TUI `/status` confirmed GPT-6-Luna max and `harness-eval (workspace, never)`; this profile applies to tool children, while the TUI parent is a host process, not a VM.

T17 completes pilot pair 12/12 (24/24 model runs). Condition order is balanced at six v1→v2 and six v2→v1 pairs. The separate full evaluation remains at 0/36 pairs (0/72 runs); run that batch separately across the 20 task types and 16 predeclared variants.
