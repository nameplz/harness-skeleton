import json
import re
from pathlib import Path

import yaml

WORKFLOW = Path('.github/workflows/ci.yml')
SHA_PATTERN = re.compile(r'^[0-9a-f]{40}$')

class WorkflowLoader(yaml.SafeLoader):
    yaml_implicit_resolvers = {
        first: [(tag, pattern) for tag, pattern in resolvers if tag != 'tag:yaml.org,2002:bool']
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

WorkflowLoader.add_implicit_resolver(
    'tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$', re.IGNORECASE), list('tTfF')
)

def unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f'duplicate YAML key: {key!r}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result

WorkflowLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)

results = {}
def check(name, passed, detail):
    results[name] = {'status': 'pass' if passed else 'fail', 'detail': detail}

try:
    text = WORKFLOW.read_text(encoding='utf-8')
    document = yaml.load(text, Loader=WorkflowLoader)
    if not isinstance(document, dict):
        raise ValueError('workflow root must be a mapping')
except Exception as exc:
    check('workflow_yaml', False, f'{type(exc).__name__}: {exc}')
    for name in ('triggers', 'path_filters', 'permissions', 'python_matrix', 'pinned_actions', 'checkout_credentials', 'install_and_test', 'shell_safety'):
        check(name, False, 'workflow could not be parsed')
else:
    check('workflow_yaml', True, 'YAML parses as a unique-key mapping')
    triggers = document.get('on')
    required_paths = ['.github/workflows/ci.yml', 'README.md', 'pyproject.toml', 'src/**', 'tests/**']
    trigger_ok = (
        isinstance(triggers, dict)
        and set(triggers) == {'push', 'pull_request'}
        and all(isinstance(value, dict) and set(value) == {'paths'} and value.get('paths') == required_paths
                for value in triggers.values())
    )
    check('triggers', trigger_ok, 'push and pull_request use the same exact relevant path filters')
    check('path_filters', trigger_ok, 'filters include the workflow, package metadata, README, source, and tests')
    check('permissions', document.get('permissions') == {'contents': 'read'}, 'contents: read is the only token permission')
    jobs = document.get('jobs')
    job = jobs.get('test') if isinstance(jobs, dict) and set(jobs) == {'test'} else None
    check('job_gate', isinstance(job, dict) and 'if' not in job and 'permissions' not in job,
          'the single test job runs on every configured event without broader job-level permissions')
    matrix = job.get('strategy', {}).get('matrix', {}).get('python-version') if isinstance(job, dict) else None
    check('python_matrix', [str(item) for item in matrix] == ['3.11', '3.12', '3.13'] if isinstance(matrix, list) else False,
          'tests Python 3.11, 3.12, and 3.13')
    steps = job.get('steps') if isinstance(job, dict) else None
    steps = steps if isinstance(steps, list) else []
    uses = [step.get('uses') for step in steps if isinstance(step, dict) and 'uses' in step]
    expected_actions = {'actions/checkout', 'actions/setup-python'}
    parsed_uses = []
    pins_valid = True
    for item in uses:
        if not isinstance(item, str) or '@' not in item:
            pins_valid = False
            continue
        name, revision = item.rsplit('@', 1)
        parsed_uses.append(name)
        pins_valid &= name in expected_actions and bool(SHA_PATTERN.fullmatch(revision))
    check('pinned_actions', pins_valid and set(parsed_uses) == expected_actions and len(parsed_uses) == 2,
          'only checkout and setup-python, each pinned to a full 40-character commit SHA')
    checkout = next((step for step in steps if isinstance(step, dict) and str(step.get('uses', '')).startswith('actions/checkout@')), {})
    check('checkout_credentials', checkout.get('with', {}).get('persist-credentials') is False,
          'checkout credentials are not persisted')
    setup = next((step for step in steps if isinstance(step, dict) and str(step.get('uses', '')).startswith('actions/setup-python@')), {})
    check('setup_python_matrix', setup.get('with', {}).get('python-version') == '${{ matrix.python-version }}',
          'setup-python consumes the declared matrix version')
    run_commands = [step.get('run') for step in steps if isinstance(step, dict) and 'run' in step]
    command_lines = [line.strip() for command in run_commands if isinstance(command, str) for line in command.splitlines() if line.strip()]
    expected_commands = ['python -m pip install . pytest', 'python -m pytest -q']
    check('install_and_test', len(run_commands) == 2 and command_lines == expected_commands,
          'runs only the required package installation and full pytest commands')
    shell_safe = all(isinstance(command, str) and '${{' not in command and 'github.event' not in command.lower() for command in run_commands)
    no_secrets = re.search(r'\bsecrets\s*\.', text, re.IGNORECASE) is None and 'pull_request_target' not in text
    check('shell_safety', shell_safe and no_secrets, 'no event/user expressions in run commands and no secrets or pull_request_target')
    ubuntu = isinstance(job, dict) and isinstance(job.get('runs-on'), str) and job['runs-on'].startswith('ubuntu-')
    check('hosted_runner', ubuntu, 'uses an Ubuntu hosted runner')

print(json.dumps(results, sort_keys=True))
raise SystemExit(0 if all(item['status'] == 'pass' for item in results.values()) else 1)
