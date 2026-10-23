from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def run(command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {'exit_code': result.returncode, 'output': result.stdout}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--condition', choices=('baseline', 'candidate', 'positive-control'), required=True)
    parser.add_argument('--patch', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (args.condition == 'baseline') != (args.patch is None):
        parser.error('baseline has no patch; candidate and positive-control require --patch')

    manifest = json.loads(args.manifest.read_text())
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    source = output / 'source'
    for entry in manifest['files']:
        src = args.snapshot / entry['path']
        data = src.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise SystemExit(f'pinned snapshot hash mismatch: {entry["path"]}')
        dst = source / entry['path']
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    changed = []
    if args.patch:
        parsed = subprocess.run(['git', 'apply', '--numstat', str(args.patch)], check=True, text=True, stdout=subprocess.PIPE).stdout
        changed = sorted(line.split('\t', 2)[2] for line in parsed.splitlines())
        if changed != ['README.md']:
            raise SystemExit(f'product scope must be README.md only; got {changed}')
        subprocess.run(['git', 'apply', '--unidiff-zero', '--check', str(args.patch)], cwd=source, check=True)
        subprocess.run(['git', 'apply', '--unidiff-zero', str(args.patch)], cwd=source, check=True)

    env = {key: value for key, value in os.environ.items() if key in {'PATH', 'LANG', 'LC_ALL'}}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    semantic = Path(__file__).with_name('semantic.py').read_text(encoding='utf-8')
    results = {
        'condition': args.condition,
        'changed_files': changed,
        'snapshot_manifest_sha256': hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        'host_grader_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'semantic_sha256': hashlib.sha256(semantic.encode()).hexdigest(),
        'semantic': run([os.environ.get('PYTHON', 'python3'), '-I', '-B', '-c', semantic], source, env),
    }
    good = results['semantic']['exit_code'] == 0 and (args.condition == 'baseline' or changed == ['README.md'])
    if args.condition == 'baseline':
        results['status'] = 'expected_fail' if results['semantic']['exit_code'] != 0 else 'calibration_error'
    else:
        results['status'] = 'pass' if good else 'fail'
    (output / 'grade.json').write_text(json.dumps(results, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'condition': args.condition, 'status': results['status'], 'changed_files': changed,
                      'semantic': results['semantic']['output'][-3000:]}, indent=2, ensure_ascii=False))
    return 0 if results['status'] in {'pass', 'expected_fail'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
