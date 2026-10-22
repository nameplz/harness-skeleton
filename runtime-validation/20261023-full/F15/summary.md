# F15 — T11 legacy channel fallback

Both conditions passed the frozen host grader: offline wheel build/install, full project suite, all five local channel semantics, and exact three-file scope. v1 passed all three independent reviews after adding an assertion that listed-channel input still replies through the legacy channel. v2 passed the captured final code and test reviews after fixing configuration validation order and asserting reply routing; a separate v2 security-review result was not captured.

v1 passed 90 tests and v2 passed 67. Candidate-side Git status or commit operations were blocked by protected system configuration/sandbox permissions, so neither condition created a candidate commit. No hosted CI, network, live Discord/Orca service, publication, push, or merge was used. Token usage and exact model-turn counts are unknown.

See the frozen task, calibration, setup and run records, patches, host grades, and pair result in this directory.
