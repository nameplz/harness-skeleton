# F24 — T10 authenticated `/orca doctor`

F24 followed the frozen v2-then-v1 order with a fresh Codex conversation for each condition. v2 passed the frozen host grader, the 59-test installed-wheel suite, all 9 semantic checks, and independent code/security reviews.

v1 passed the 59-test installed-wheel suite and the named compatibility test. Its first security review found that Orca-supplied identity/state strings could spoof the Discord code-span diagnostic with newlines or backticks. The second implementation attempt sanitizes identifiers, allowlists displayed states, and adds malicious-value regression coverage; code, test, and security re-reviews passed.

The frozen host grader gives v1 a raw fail on only `healthy_status_and_identity`: the response uses Korean `연결됨` (“connected”), while the grader accepts `정상`, `healthy`, or English `connected`. The grader was frozen before either run and was not edited after the result; this possible locale false negative is recorded without overriding the raw grade. The pair is therefore not accepted under the frozen result.

The Harness risk/full checks were unavailable because the pinned checkout lacks the required runner/configuration. Candidate suites emitted two temporary-directory cleanup warnings; host suites passed cleanly. Feature-branch creation was denied, so no candidate commit was made. The TUI displayed startup hook exit code 125 without a captured cause; the task run did not invoke project hooks. No network, live services, push, publication, or merge occurred.

See [frozen task](task.md), [acceptance](acceptance.json), [freeze record](freeze.json), [baseline grade](baseline-grade.json), [positive control](positive-control-grade.json), [v2 run](v2-run.json) / [patch](v2-final.patch) / [grade](v2-grade.json), [v1 run](v1-run.json) / [patch](v1-final.patch) / [grade](v1-grade.json), and [pair results](results.json).
