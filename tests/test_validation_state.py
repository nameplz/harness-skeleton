from dataclasses import replace
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.runtime_fixtures import materialize_fixture
from evals.runtime_grader import _applied_validation_passed, _applied_validation_state, grade_fixture
from scripts.command_runner import CommandResult
from scripts.harness import run_checks


class ValidationStateTests(unittest.TestCase):
    def test_contradictory_limit_flags_and_malformed_checks_never_claim_validation(self):
        digest = 'f' * 64
        report = {'profile': 'quick', 'ok': False, 'evidence_unchanged': True,
                  'evidence': {'config_sha256': digest}, 'evidence_after': {'config_sha256': digest}}
        base = {'started': True, 'returncode': 0, 'passed': True, 'timed_out': False, 'output_limited': False}
        for check in ({**base, 'timed_out': True}, {**base, 'output_limited': True},
                      {**base, 'returncode': 124, 'passed': False, 'timed_out': True, 'output_limited': True}):
            result = CommandResult(1, json.dumps({**report, 'checks': [check]}))
            with self.subTest(check=check):
                self.assertEqual('unknown', _applied_validation_state(result, digest))
                self.assertFalse(_applied_validation_passed(result, digest))
        for checks in ('claimed success', {'claimed': True}, [True], [{}]):
            result = CommandResult(0, json.dumps({**report, 'ok': True, 'checks': checks}))
            with self.subTest(checks=checks):
                self.assertEqual('unknown', _applied_validation_state(result, digest))
                self.assertFalse(_applied_validation_passed(result, digest))

    def test_actual_bounded_host_checks_distinguish_pass_failure_and_timeout(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            trusted = root / 'trusted'; (trusted / '.harness').mkdir(parents=True)
            for program, expected in (('pass', 'passed'), ('raise SystemExit(3)', 'failed'),
                                      ('import time; time.sleep(2)', 'timed_out')):
                (fixture.root / 'check.py').write_text(program + '\n')
                command = [sys.executable, '-I', '-B', 'check.py']
                (trusted / '.harness/config.toml').write_text(
                    'schema = 2\n[checks]\nquick = ' + json.dumps([command]) + '\nfull = ' + json.dumps([command]) + '\n')
                with patch('scripts.harness.CHECK_TIMEOUT_SECONDS', 0.15):
                    report = run_checks(fixture.root, 'quick', config_root=trusted)
                result = CommandResult(0 if report['ok'] else 1, json.dumps(report))
                digest = report['evidence']['config_sha256']
                self.assertEqual(expected, _applied_validation_state(result, digest))
                self.assertEqual('unknown', _applied_validation_state(result, 'f' * 64))
                changed = {**report, 'evidence_unchanged': False}
                self.assertEqual('unknown', _applied_validation_state(replace(result, output=json.dumps(changed)), digest))
                self.assertEqual('unknown', _applied_validation_state(replace(result, timed_out=True), digest))

    def test_candidate_claims_and_unstarted_validation_do_not_supply_state(self):
        claims = CommandResult(0, '{"actual_validation_state":"passed","ok":true}')
        self.assertEqual('unknown', _applied_validation_state(claims, 'f' * 64))
        self.assertEqual('unknown', _applied_validation_state(None, 'f' * 64))
        self.assertEqual('unknown', _applied_validation_state(replace(claims, started=False), 'f' * 64))

    def test_all_early_grader_returns_include_unknown_state_without_execution(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            with patch('evals.runtime_grader.run_bounded_command') as runner:
                grade = grade_fixture(fixture, tool_trace=None, trusted_config_root=root / 'missing')
            self.assertEqual('unknown', grade['actual_validation_state'])
            runner.assert_not_called()
            (fixture.root / 'README.md').unlink()
            (fixture.root / 'README.md').symlink_to(root / 'outside')
            with patch('evals.runtime_grader.run_bounded_command') as runner:
                grade = grade_fixture(fixture, tool_trace=None)
            self.assertEqual('unknown', grade['actual_validation_state'])
            runner.assert_not_called()
