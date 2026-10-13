import unittest

from evals.native_telemetry import validate_account


class NativeTelemetryTests(unittest.TestCase):
    def test_sparse_nullable_and_signed_schema_fields(self):
        for limits in ({}, {'primary': {'usedPercent': -1}},
                       {'spendControlReached': True, 'planType': None},
                       {'individualLimit': {'limit': '10', 'used': '2', 'remainingPercent': 80, 'resetsAt': 1}}):
            validate_account('account/rateLimits/updated', {'rateLimits': limits})
        validate_account('account/updated', {'authMode': None, 'planType': None})

    def test_malformed_account_types_raise_safe_value_error(self):
        for params in ({'authMode': []}, {'planType': {}}, {'planType': 'other'}, {'token': 'secret'}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                validate_account('account/updated', params)
        for limits in ({'planType': []}, {'rateLimitReachedType': {}}, {'spendControlReached': {}},
                       {'primary': {'usedPercent': None}}, {'primary': {'usedPercent': True}},
                       {'individualLimit': {'limit': None, 'used': '2', 'remainingPercent': 80, 'resetsAt': 1}},
                       {'credits': {'hasCredits': False, 'unlimited': None}}, {'unknown': 'secret'}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                validate_account('account/rateLimits/updated', {'rateLimits': limits})
