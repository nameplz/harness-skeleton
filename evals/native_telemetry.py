"""Validate native account bookkeeping without retaining account values."""

from evals.native_session import AUTH_MODES, PLAN_TYPES

REACHED = frozenset({'rate_limit_reached', 'workspace_owner_credits_depleted',
    'workspace_member_credits_depleted', 'workspace_owner_usage_limit_reached',
    'workspace_member_usage_limit_reached'})
FIELDS = frozenset({'credits', 'individualLimit', 'limitId', 'limitName', 'normalModelSlug',
    'planType', 'primary', 'secondary', 'rateLimitReachedType', 'spendControlReached'})


def _object(value: object, allowed: set | frozenset, required: set = frozenset()) -> dict:
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise ValueError('invalid native telemetry shape')
    return value


def _values(value: dict, strings: tuple[str, ...] = (), integers: tuple[str, ...] = (),
            booleans: tuple[str, ...] = ()) -> None:
    for key in strings:
        if value.get(key) is not None and (not isinstance(value[key], str) or len(value[key]) > 512):
            raise ValueError('invalid native telemetry text')
    for key in integers:
        if value.get(key) is not None and type(value[key]) is not int:
            raise ValueError('invalid native telemetry integer')
    for key in booleans:
        if type(value.get(key)) is not bool:
            raise ValueError('invalid native telemetry boolean')


def validate_account(method: str, params: object) -> None:
    if method == 'account/updated':
        value = _object(params, {'authMode', 'planType'})
        if not _enum(value.get('authMode'), AUTH_MODES) or not _enum(value.get('planType'), PLAN_TYPES):
            raise ValueError('invalid native account enumeration')
        return
    value = _object(params, {'rateLimits'}, {'rateLimits'})
    limits = _object(value['rateLimits'], FIELDS)
    _values(limits, ('limitId', 'limitName', 'normalModelSlug'))
    if not _enum(limits.get('planType'), PLAN_TYPES) or not _enum(limits.get('rateLimitReachedType'), REACHED):
        raise ValueError('invalid native rate-limit enumeration')
    for key in ('primary', 'secondary'):
        if limits.get(key) is not None:
            window = _object(limits[key], {'usedPercent', 'resetsAt', 'windowDurationMins'}, {'usedPercent'})
            _values(window, integers=('usedPercent', 'resetsAt', 'windowDurationMins'))
            if type(window['usedPercent']) is not int:
                raise ValueError('missing native rate-limit usage')
    if limits.get('credits') is not None:
        credits = _object(limits['credits'], {'hasCredits', 'unlimited', 'balance'}, {'hasCredits', 'unlimited'})
        _values(credits, ('balance',), booleans=('hasCredits', 'unlimited'))
    if limits.get('spendControlReached') is not None and type(limits['spendControlReached']) is not bool:
        raise ValueError('invalid native spending state')
    for key in ('individualLimit',):
        if limits.get(key) is not None:
            spend = _object(limits[key], {'limit', 'used', 'remainingPercent', 'resetsAt'},
                            {'limit', 'used', 'remainingPercent', 'resetsAt'})
            _values(spend, ('limit', 'used'), ('remainingPercent', 'resetsAt'))
            if any(spend[k] is None for k in spend):
                raise ValueError('missing native spending limit')


def _enum(value: object, choices: frozenset) -> bool:
    return value is None or isinstance(value, str) and value in choices
