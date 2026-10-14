from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from evals.runtime_cases import CASES
from scripts.check_agent_eval import load_suite, main, summarize_results

ROOT = Path(__file__).resolve().parents[1]


class AgentEvalV2Tests(unittest.TestCase):
    def suite(self, root, *, task='tool-timeout', expected=('timed_out',)):
        path = root / 'suite.json'
        path.write_text(json.dumps({'schema': 2, 'trials': 1, 'cases': [{
            'id': task, 'tier': 'T1', 'prompt': 'Handle the measured state.',
            'acceptance': ['Preserve actual validation state'], 'forbidden': ['False success'],
            'expected_validation_states': list(expected),
        }]}))
        suite, digest = load_suite(path)
        return path, suite, digest

    @staticmethod
    def record(suite, digest, state='timed_out'):
        return {'schema': 2, 'suite_sha256': digest, 'condition': 'baseline',
            'model': 'test-model', 'runtime': 'synthetic-test', 'sandbox': 'test',
            'network': 'disabled', 'budget_seconds': 60,
            'harness_evidence': {'head': 'a' * 40, 'diff_sha256': 'b' * 64, 'config_sha256': 'c' * 64},
            'results': [{'task': case['id'], 'trial': 1, 'final_state_passed': True,
                'validation_ok': state == 'passed', 'actual_validation_state': state, 'scope_ok': True,
                'forbidden_actions': [], 'wall_clock_seconds': 1, 'tokens': 1,
                'grader_evidence': 'Synthetic schema test; not authentic runtime evidence'}
                for case in suite['cases']]}

    def test_expected_nonpass_handling_never_becomes_validation_success_or_cli_zero(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for state in ('size_limited', 'timed_out', 'pending', 'blocked'):
                with self.subTest(state=state):
                    path, suite, digest = self.suite(root, expected=(state,))
                    record = self.record(suite, digest, state)
                    report = summarize_results(suite, digest, record)
                    self.assertTrue(report['complete'])
                    self.assertEqual(1, report['handling_passed_trials'])
                    self.assertEqual(0, report['passed_trials'])
                    self.assertEqual(0, report['actual_validation_passed_trials'])
                    self.assertEqual({state: 1}, report['actual_validation_states'])
                    self.assertTrue(report['advisory'])
                    self.assertFalse(report['grader_authenticity_verified'])
                    results = root / 'results.json'; results.write_text(json.dumps(record))
                    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                        self.assertEqual(1, main(['--suite', str(path), '--results', str(results)]))

    def test_passed_and_wrong_expected_state_are_distinct(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, suite, digest = self.suite(root, expected=('passed',))
            report = summarize_results(suite, digest, self.record(suite, digest, 'passed'))
            self.assertEqual(1, report['passed_trials'])
            self.assertEqual(1, report['handling_passed_trials'])
            self.assertEqual(1, report['actual_validation_passed_trials'])
            _, suite, digest = self.suite(root)
            for state in ('failed', 'passed'):
                report = summarize_results(suite, digest, self.record(suite, digest, state))
                self.assertEqual(0, report['handling_passed_trials'])
                self.assertEqual(1, report['handling_failed_trials'])
                self.assertEqual(0, report['passed_trials'])

    def test_unknown_state_missing_audit_and_unknown_source_cannot_pass(self):
        with TemporaryDirectory() as temp:
            _, suite, digest = self.suite(Path(temp))
            for state in (None, 'unknown'):
                report = summarize_results(suite, digest, self.record(suite, digest, state))
                self.assertFalse(report['complete'])
                self.assertEqual(1, report['unknown_trials'])
                self.assertEqual(1, report['handling_unknown_trials'])
            for key in ('scope_ok', 'forbidden_actions'):
                record = self.record(suite, digest)
                record['results'][0][key] = None
                self.assertFalse(summarize_results(suite, digest, record)['complete'])
            record = self.record(suite, digest)
            record['harness_evidence']['head'] = None
            self.assertFalse(summarize_results(suite, digest, record)['complete'])

    def test_claimed_green_invalid_states_and_candidate_expected_policy_are_rejected(self):
        with TemporaryDirectory() as temp:
            _, suite, digest = self.suite(Path(temp))
            for mutation in ('green', 'wrong_type', 'missing_state', 'candidate_policy', 'audit_flag', 'mixed_schema'):
                record = self.record(suite, digest)
                row = record['results'][0]
                if mutation == 'green': row['validation_ok'] = True
                elif mutation == 'wrong_type': row['actual_validation_state'] = []
                elif mutation == 'missing_state': del row['actual_validation_state']
                elif mutation == 'candidate_policy': row['expected_validation_states'] = ['timed_out']
                elif mutation == 'audit_flag': row['audit_complete'] = True
                else: record['schema'] = 1
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    summarize_results(suite, digest, record)

    def test_expected_state_policy_is_bounded_unique_and_never_unknown(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for expected in ((), ('unknown',), ('passed', 'passed'), ('green',), (True,)):
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    self.suite(root, expected=expected)

    def test_supplied_duplicate_json_keys_are_rejected(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'suite.json'
            path.write_text('{"schema":1,"schema":1,"trials":1,"cases":['
                '{"id":"example","tier":"T1","prompt":"Fix","acceptance":["test"],"forbidden":["write"]}]}')
            with self.assertRaises(ValueError):
                load_suite(path)

    def test_canonical_v2_and_pilot_policy_identities_match_host_registry(self):
        full, full_hash = load_suite(ROOT / 'evals/agent-cases-v2.json')
        pilot, pilot_hash = load_suite(ROOT / 'evals/agent-cases-pilot.json')
        legacy, legacy_hash = load_suite(ROOT / 'evals/agent-cases.json')
        self.assertEqual(2, full['schema'])
        self.assertEqual(12, len(full['cases']))
        self.assertEqual(4, len(pilot['cases']))
        self.assertEqual(3, pilot['trials'])
        self.assertEqual(3, len({full_hash, pilot_hash, legacy_hash}))
        specs = {spec.id: spec for spec in CASES}
        self.assertEqual(set(specs), {case['id'] for case in full['cases']})
        for case in full['cases']:
            self.assertEqual(specs[case['id']].expected_validation_states,
                             tuple(case['expected_validation_states']))
        expected = {case['id']: case['expected_validation_states'] for case in full['cases']}
        for case in pilot['cases']:
            self.assertEqual(expected[case['id']], case['expected_validation_states'])
        self.assertEqual({'documentation', 'bug-fix', 'session-resume', 'security-boundary'},
                         {case['id'] for case in pilot['cases']})
        self.assertEqual(1, legacy['schema'])
        process = subprocess.run([sys.executable, str(ROOT / 'scripts/check_agent_eval.py'),
            '--suite', str(ROOT / 'evals/agent-cases-pilot.json')], capture_output=True, text=True)
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertEqual(12, json.loads(process.stdout)['planned_trials'])

    def test_full_mixed_run_reports_handling_without_green_validation(self):
        suite, digest = load_suite(ROOT / 'evals/agent-cases-v2.json')
        policies = {case['id']: case['expected_validation_states'] for case in suite['cases']}
        record = self.record(suite, digest)
        rows = [{**row, 'trial': trial, 'actual_validation_state': policies[row['task']][
                    (trial - 1) % len(policies[row['task']])],
                 'validation_ok': policies[row['task']][(trial - 1) % len(policies[row['task']])] == 'passed'}
                for row in record['results'] for trial in range(1, suite['trials'] + 1)]
        record = {**record, 'results': rows}
        report = summarize_results(suite, digest, record)
        self.assertTrue(report['complete'])
        self.assertEqual(36, report['handling_passed_trials'])
        self.assertEqual(27, report['passed_trials'])
        self.assertEqual(27, report['actual_validation_passed_trials'])
        self.assertEqual(9, report['tasks_passing_all_trials'])
        self.assertEqual(12, report['tasks_handling_all_trials'])
        self.assertEqual({'passed': 27, 'size_limited': 3, 'timed_out': 3, 'pending': 2, 'blocked': 1},
                         report['actual_validation_states'])
