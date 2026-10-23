# F36 — T17 minimal CI workflow

The planned order was v2 then v1. Both conditions passed the frozen host grader: the workflow stays within the one-file scope, parses with unique keys, has the exact trigger/permission/matrix/action/install/test requirements, and passes the offline package build/install and all 58 existing tests. Both code and security reviews passed; v1 also passed its test review.

See the [frozen task](task.md), [acceptance](acceptance.json), [v2 record](v2-run.json), [v1 record](v1-run.json), and [host grades](v2-host-grade.json) / [v1-host-grade.json). The candidate commits could not write the local Git index, so both patches are retained separately.

Limitations: GitHub Actions was not dispatched, so hosted Python 3.11/3.12 execution is unmeasured. The snapshot lacks `scripts/harness.py` and `.harness/config.toml`. A metadata-only pip version probe in v2 omitted offline variables without accessing an index. The first host-grader invocation used Python 3.9 without PyYAML; the same frozen grader passed when rerun with the calibrated Python 3.13 evaluator runtime.
