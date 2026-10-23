import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
from orca_discord_bridge import orca

results = {}
def report(name, ok, detail):
    results[name] = {"status": "pass" if ok else "fail", "detail": detail}

with tempfile.TemporaryDirectory(prefix="t14-grader-") as temp_name:
    temp = Path(temp_name)
    cli = temp / "fake-orca"
    cli.write_text("#!" + sys.executable + "\n" + '''
import json, os, sys, time
from pathlib import Path
mode=os.environ.get('T14_MODE','normal')
if mode=='child':
 Path(os.environ['T14_PID_FILE']).write_text(str(os.getpid()))
 time.sleep(60)
elif mode=='nonzero':
 print('FAKE_FAILURE',file=sys.stderr);sys.exit(7)
elif mode=='nonjson':
 print('not-json')
else:
 Path(os.environ['T14_ARGS_FILE']).write_text(json.dumps(sys.argv[1:]))
 print(json.dumps({'ok':True,'result':{}}))
''' + "\n", encoding="utf-8")
    cli.chmod(0o700)
    pid_file = temp/'child.pid'
    args_file = temp/'args.json'
    marker = temp/'shell-was-used'
    os.environ['T14_PID_FILE'] = str(pid_file)
    os.environ['T14_ARGS_FILE'] = str(args_file)
    client = orca.OrcaClient(str(cli), wait_timeout_ms=1000)
    spawned = []
    original_spawn = asyncio.create_subprocess_exec
    async def track_spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        spawned.append(proc)
        return proc
    orca.asyncio.create_subprocess_exec = track_spawn

    async def run_checks():
        try:
            os.environ['T14_MODE'] = 'nonzero'
            try:
                await client._run('status', '--json', timeout=2)
                report('nonzero_error', False, 'nonzero child returned successfully')
            except orca.OrcaError as exc:
                report('nonzero_error', 'failed' in str(exc).lower(), 'nonzero exit is surfaced as OrcaError')

            os.environ['T14_MODE'] = 'nonjson'
            try:
                await client._run('status', '--json', timeout=2)
                report('non_json_error', False, 'invalid JSON child returned successfully')
            except orca.OrcaError as exc:
                report('non_json_error', 'non-json' in str(exc).lower(), 'invalid JSON is surfaced as OrcaError')

            os.environ['T14_MODE'] = 'child'
            before = len(spawned)
            try:
                await client._run('status', '--json', timeout=0.15)
                report('timeout_cleanup', False, 'timeout was not raised')
            except orca.OrcaError as exc:
                proc = spawned[-1] if len(spawned) > before else None
                report('timeout_cleanup', 'timed out' in str(exc).lower() and proc is not None and proc.returncode is not None,
                       'timeout is surfaced and direct child has exited and been reaped')
                if proc is not None and proc.returncode is None:
                    proc.kill(); await proc.communicate()

            pid_file.unlink(missing_ok=True)
            before = len(spawned)
            task = asyncio.create_task(client._run('status', '--json', timeout=30))
            for _ in range(200):
                if pid_file.exists() and len(spawned) > before:
                    break
                await asyncio.sleep(0.01)
            started = pid_file.exists() and len(spawned) > before
            task.cancel()
            try:
                await task
                cancelled = False
            except asyncio.CancelledError:
                cancelled = True
            proc = spawned[-1] if len(spawned) > before else None
            report('cancellation_cleanup', started and cancelled and proc is not None and proc.returncode is not None,
                   'cancellation propagates after direct child exits and is reaped')
            if proc is not None and proc.returncode is None:
                proc.kill(); await proc.communicate()

            os.environ['T14_MODE'] = 'normal'
            literal = f'$(touch {marker}); keep this literal'
            await client.send_terminal('term', literal)
            args = json.loads(args_file.read_text())
            report('literal_argv', literal in args and not marker.exists(),
                   'shell-like text remains one literal argv value and creates no marker')
        finally:
            for proc in spawned:
                if proc.returncode is None:
                    proc.kill(); await proc.communicate()

    try:
        asyncio.run(run_checks())
    finally:
        orca.asyncio.create_subprocess_exec = original_spawn

print(json.dumps(results, sort_keys=True))
raise SystemExit(0 if all(item["status"] == "pass" for item in results.values()) else 1)
