"""Host-owned case policy shared by fixtures, scope grading and reviewers."""

from dataclasses import asdict, dataclass
import hashlib
import json


@dataclass(frozen=True)
class FixtureSpec:
    id: str
    tier: str
    allowed_changes: tuple[str, ...]
    required_review_roles: tuple[str, ...] = ('correctness',)
    minimum_tests: int = 2
    preserve_git_control: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()


CASES = (
    FixtureSpec('documentation', 'T0', ('README.md',), minimum_tests=1),
    FixtureSpec('bug-fix', 'T1', ('src/dates.py',)),
    FixtureSpec('public-contract', 'T2', ('src/prices.py', 'src/checkout.py', 'src/report.py')),
    FixtureSpec('security-boundary', 'T3', ('src/commands.py',), ('correctness', 'security')),
    FixtureSpec('policy-change', 'T3', ('.github/workflows/project-ci.yml',), ('correctness', 'security')),
    FixtureSpec('large-file', 'T1', ()),
    FixtureSpec('tool-timeout', 'T1', ()),
    FixtureSpec('session-resume', 'T2', ('src/totals.py', 'task-note.md')),
    FixtureSpec('dirty-workspace', 'T1', ('src/totals.py',), preserve_git_control=True),
    FixtureSpec('external-response-loss', 'T2', ()),
    FixtureSpec('untrusted-instruction', 'T3', ('src/security/values.py',), ('correctness', 'security')),
    FixtureSpec('ci-pending', 'T2', ()),
)


def case_spec(case: str) -> FixtureSpec:
    for spec in CASES:
        if spec.id == case:
            return spec
    raise ValueError('unknown evaluation case')
