#!/usr/bin/env python3
"""
Harness Step Executor — phase 내 step을 순차 실행하고 자가 교정한다.

Usage:
    python3 scripts/execute.py <phase-dir> [--push]
"""

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def progress_indicator(label: str):
    """터미널 진행 표시기. with 문으로 사용하며 .elapsed 로 경과 시간을 읽는다."""
    frames = "◐◓◑◒"
    stop = threading.Event()
    t0 = time.monotonic()

    def _animate():
        idx = 0
        while not stop.wait(0.12):
            sec = int(time.monotonic() - t0)
            sys.stderr.write(f"\r{frames[idx % len(frames)]} {label} [{sec}s]")
            sys.stderr.flush()
            idx += 1
        sys.stderr.write("\r" + " " * (len(label) + 20) + "\r")
        sys.stderr.flush()

    th = threading.Thread(target=_animate, daemon=True)
    th.start()
    info = types.SimpleNamespace(elapsed=0.0)
    try:
        yield info
    finally:
        stop.set()
        th.join()
        info.elapsed = time.monotonic() - t0


class StepExecutor:
    """Phase 디렉토리 안의 step들을 순차 실행하는 하네스."""

    MAX_RETRIES = 3
    TERMINAL_STATUSES = {"completed", "blocked", "error"}
    STATUS_POLL_INTERVAL_SECONDS = 60
    STUCK_TIMEOUT_SECONDS = 1800
    CODEX_TIMEOUT_SECONDS = 1800
    FEAT_MSG = "feat({phase}): step {num} — {name}"
    CHORE_MSG = "chore({phase}): step {num} output"
    TZ = timezone(timedelta(hours=9))

    def __init__(
        self,
        phase_dir_name: str,
        *,
        auto_push: bool = False,
        status_interval_seconds: int = STATUS_POLL_INTERVAL_SECONDS,
        stuck_timeout_seconds: int = STUCK_TIMEOUT_SECONDS,
    ):
        self._root = str(ROOT)
        self._phases_dir = ROOT / "phases"
        self._phase_dir = self._phases_dir / phase_dir_name
        self._phase_dir_name = phase_dir_name
        self._top_index_file = self._phases_dir / "index.json"
        self._auto_push = auto_push
        self._status_interval_seconds = status_interval_seconds
        self._stuck_timeout_seconds = stuck_timeout_seconds
        self._codex_timeout_seconds = self.CODEX_TIMEOUT_SECONDS

        if not self._phase_dir.is_dir():
            print(f"ERROR: {self._phase_dir} not found")
            sys.exit(1)

        self._index_file = self._phase_dir / "index.json"
        if not self._index_file.exists():
            print(f"ERROR: {self._index_file} not found")
            sys.exit(1)

        idx = self._read_json(self._index_file)
        self._project = idx.get("project", "project")
        self._phase_name = idx.get("phase", phase_dir_name)
        self._total = len(idx["steps"])

    def run(self):
        self._print_header()
        self._recover_running_steps()
        self._check_blockers()
        self._checkout_branch()
        guardrails = self._load_guardrails()
        self._ensure_created_at()
        self._execute_all_steps(guardrails)
        self._finalize()

    # --- timestamps ---

    def _stamp(self) -> str:
        return datetime.now(self.TZ).strftime("%Y-%m-%dT%H:%M:%S%z")

    @staticmethod
    def _parse_stamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None

    # --- JSON I/O ---

    @staticmethod
    def _read_json(p: Path) -> dict:
        return json.loads(p.read_text(encoding="utf-8"))

    @staticmethod
    def _write_json(p: Path, data: dict):
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- git ---

    def _run_git(self, *args) -> subprocess.CompletedProcess:
        cmd = ["git"] + list(args)
        return subprocess.run(cmd, cwd=self._root, capture_output=True, text=True)

    def _checkout_branch(self):
        branch = f"feat-{self._phase_name}"

        r = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
        if r.returncode != 0:
            print(f"  ERROR: git을 사용할 수 없거나 git repo가 아닙니다.")
            print(f"  {r.stderr.strip()}")
            sys.exit(1)

        if r.stdout.strip() == branch:
            return

        r = self._run_git("rev-parse", "--verify", branch)
        r = self._run_git("checkout", branch) if r.returncode == 0 else self._run_git("checkout", "-b", branch)

        if r.returncode != 0:
            print(f"  ERROR: 브랜치 '{branch}' checkout 실패.")
            print(f"  {r.stderr.strip()}")
            print(f"  Hint: 변경사항을 stash하거나 commit한 후 다시 시도하세요.")
            sys.exit(1)

        print(f"  Branch: {branch}")

    def _commit_step(self, step_num: int, step_name: str):
        output_rel = f"phases/{self._phase_dir_name}/step{step_num}-output.json"
        index_rel = f"phases/{self._phase_dir_name}/index.json"

        self._run_git("add", "-A")
        self._run_git("reset", "HEAD", "--", output_rel)
        self._run_git("reset", "HEAD", "--", index_rel)

        if self._run_git("diff", "--cached", "--quiet").returncode != 0:
            msg = self.FEAT_MSG.format(phase=self._phase_name, num=step_num, name=step_name)
            r = self._run_git("commit", "-m", msg)
            if r.returncode == 0:
                print(f"  Commit: {msg}")
            else:
                print(f"  WARN: 코드 커밋 실패: {r.stderr.strip()}")

        self._run_git("add", "-A")
        if self._run_git("diff", "--cached", "--quiet").returncode != 0:
            msg = self.CHORE_MSG.format(phase=self._phase_name, num=step_num)
            r = self._run_git("commit", "-m", msg)
            if r.returncode != 0:
                print(f"  WARN: housekeeping 커밋 실패: {r.stderr.strip()}")

    # --- top-level index ---

    def _update_top_index(self, status: str):
        if not self._top_index_file.exists():
            return
        top = self._read_json(self._top_index_file)
        ts = self._stamp()
        for phase in top.get("phases", []):
            if phase.get("dir") == self._phase_dir_name:
                phase["status"] = status
                ts_key = {"completed": "completed_at", "error": "failed_at", "blocked": "blocked_at"}.get(status)
                if ts_key:
                    phase[ts_key] = ts
                break
        self._write_json(self._top_index_file, top)

    # --- guardrails & context ---

    def _load_guardrails(self) -> str:
        sections = []
        agents_md = ROOT / "AGENTS.md"
        if agents_md.exists():
            sections.append(f"## 프로젝트 규칙 (AGENTS.md)\n\n{agents_md.read_text()}")
        docs_dir = ROOT / "docs"
        if docs_dir.is_dir():
            for doc in sorted(docs_dir.glob("*.md")):
                sections.append(f"## {doc.stem}\n\n{doc.read_text()}")
        return "\n\n---\n\n".join(sections) if sections else ""

    @staticmethod
    def _build_step_context(index: dict) -> str:
        lines = [
            f"- Step {s['step']} ({s['name']}): {s['summary']}"
            for s in index["steps"]
            if s["status"] == "completed" and s.get("summary")
        ]
        if not lines:
            return ""
        return "## 이전 Step 산출물\n\n" + "\n".join(lines) + "\n\n"

    def _build_preamble(self, guardrails: str, step_context: str,
                        prev_error: Optional[str] = None) -> str:
        retry_section = ""
        if prev_error:
            retry_section = (
                f"\n## ⚠ 이전 시도 실패 — 아래 에러를 반드시 참고하여 수정하라\n\n"
                f"{prev_error}\n\n---\n\n"
            )
        return (
            f"당신은 {self._project} 프로젝트의 개발자입니다. 아래 step을 수행하세요.\n\n"
            f"{guardrails}\n\n---\n\n"
            f"{step_context}{retry_section}"
            f"## 작업 규칙\n\n"
            f"1. 이전 step에서 작성된 코드를 확인하고 일관성을 유지하라.\n"
            f"2. 이 step에 명시된 작업만 수행하라. 추가 기능이나 파일을 만들지 마라.\n"
            f"3. 기존 테스트를 깨뜨리지 마라.\n"
            f"4. AC(Acceptance Criteria) 검증을 직접 실행하라.\n"
            f"5. /phases/{self._phase_dir_name}/index.json의 해당 step만 정확히 업데이트하라:\n"
            f"   - 실행 중에는 status를 \"running\"으로 유지하고, "
            f"{self._status_interval_seconds}초마다 "
            f"last_progress_at과 progress_message를 갱신하라.\n"
            f"   - last_progress_at은 예: {self._stamp()} 형식으로 기록하라.\n"
            f"   - AC 통과 → \"completed\" + \"summary\" 필드에 이 step의 산출물을 한 줄로 요약\n"
            f"   - {self.MAX_RETRIES}회 수정 시도 후에도 실패 → \"error\" + \"error_message\" 기록\n"
            f"   - 사용자 개입이 필요한 경우 (API 키, 인증, 수동 설정 등) → \"blocked\" + \"blocked_reason\" 기록 후 즉시 중단\n"
            f"   - 다른 step의 status, summary, error_message, blocked_reason, "
            f"last_progress_at, progress_message는 변경하지 마라.\n"
            f"6. git commit은 실행하지 마라. 커밋은 scripts/execute.py가 담당한다.\n\n---\n\n"
        )

    # --- Codex 호출 ---

    def _invoke_codex(self, step: dict, preamble: str) -> dict:
        step_num, step_name = step["step"], step["name"]
        step_file = self._phase_dir / f"step{step_num}.md"

        if not step_file.exists():
            print(f"  ERROR: {step_file} not found")
            sys.exit(1)

        prompt = preamble + step_file.read_text()
        started = time.monotonic()
        cmd = [
            "codex",
            "exec",
            "-c",
            "approval_policy=never",
            "-s",
            "workspace-write",
            "--json",
            prompt,
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            stdout_path = Path(tmpdir) / "stdout.txt"
            stderr_path = Path(tmpdir) / "stderr.txt"
            with stdout_path.open("w+", encoding="utf-8") as stdout_file:
                with stderr_path.open("w+", encoding="utf-8") as stderr_file:
                    process = subprocess.Popen(
                        cmd,
                        cwd=self._root,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        text=True,
                        start_new_session=True,
                    )
                    monitor = self._monitor_codex_process(process, step)

                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read()
                    stderr = stderr_file.read()

        returncode = process.returncode
        if monitor["stuck"]:
            returncode = returncode if returncode is not None else -9
            self._mark_step_error(step_num, monitor["reason"])

        if monitor["timed_out"]:
            returncode = returncode if returncode is not None else -9
            self._mark_step_error(step_num, monitor["reason"])

        if returncode != 0 and not monitor.get("terminal_status"):
            print(f"\n  WARN: Codex가 비정상 종료됨 (code {returncode})")
            if stderr:
                print(f"  stderr: {stderr[:500]}")

        out_path = self._phase_dir / f"step{step_num}-output.json"
        output = self._build_step_output(
            step=step,
            prompt=prompt,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            monitor=monitor,
            duration_seconds=time.monotonic() - started,
            output_path=out_path,
        )
        self._write_json(out_path, output)

        return output

    def _relative_path(self, path: Path) -> str:
        try:
            return path.relative_to(Path(self._root)).as_posix()
        except ValueError:
            return path.as_posix()

    def _build_step_output(
        self,
        *,
        step: dict,
        prompt: str,
        stdout: str,
        stderr: str,
        returncode: int,
        monitor: dict,
        duration_seconds: float,
        output_path: Path,
    ) -> dict:
        step_num = step["step"]
        step_name = step["name"]
        step_file = self._phase_dir / f"step{step_num}.md"
        snapshot = self._current_step_snapshot(step_num)
        step_status = {
            "status": snapshot.get("status"),
            "summary": snapshot.get("summary"),
            "errorMessage": snapshot.get("error_message"),
            "blockedReason": snapshot.get("blocked_reason"),
            "progressMessage": snapshot.get("progress_message"),
        }

        return {
            "schemaVersion": 2,
            "phase": self._phase_name,
            "step": step_num,
            "name": step_name,
            "attempt": snapshot.get("attempt"),
            "exitCode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stuck": monitor["stuck"],
            "timedOut": monitor["timed_out"],
            "terminalStatus": monitor.get("terminal_status"),
            "durationSeconds": round(duration_seconds, 3),
            "timestamps": {
                "startedAt": snapshot.get("started_at"),
                "lastProgressAt": snapshot.get("last_progress_at"),
                "recordedAt": self._stamp(),
            },
            "paths": {
                "stepFile": self._relative_path(step_file),
                "indexFile": self._relative_path(self._index_file),
                "outputFile": self._relative_path(output_path),
            },
            "command": {
                "program": "codex",
                "args": [
                    "exec",
                    "-c",
                    "approval_policy=never",
                    "-s",
                    "workspace-write",
                    "--json",
                ],
                "cwd": self._root,
                "promptBytes": len(prompt.encode("utf-8")),
            },
            "process": {
                "exitCode": returncode,
                "stdoutBytes": len(stdout.encode("utf-8")),
                "stderrBytes": len(stderr.encode("utf-8")),
            },
            "monitor": {
                "stuck": monitor["stuck"],
                "timedOut": monitor["timed_out"],
                "terminalStatus": monitor.get("terminal_status"),
                "reason": monitor.get("reason", ""),
            },
            "stepStatus": step_status,
        }

    def _monitor_codex_process(self, process: subprocess.Popen, step: dict) -> dict:
        step_num = step["step"]
        step_name = step["name"]
        started = time.monotonic()

        while True:
            elapsed = time.monotonic() - started
            if elapsed >= self._codex_timeout_seconds:
                reason = f"Codex timeout after {self._codex_timeout_seconds}s"
                self._terminate_process(process)
                return {
                    "stuck": False,
                    "timed_out": True,
                    "reason": reason,
                    "terminal_status": None,
                }

            wait_seconds = min(self._status_interval_seconds, self._codex_timeout_seconds - elapsed)
            try:
                process.wait(timeout=wait_seconds)
                return {
                    "stuck": False,
                    "timed_out": False,
                    "reason": "",
                    "terminal_status": None,
                }
            except subprocess.TimeoutExpired:
                snapshot = self._current_step_snapshot(step_num)
                status = snapshot.get("status", "unknown")
                progress = str(snapshot.get("progress_message", ""))[:160]
                progress_age = self._progress_age_seconds(snapshot)
                age_text = "unknown" if progress_age is None else f"{int(progress_age)}s"
                print(
                    f"\n  Status check: Step {step_num} ({step_name}) "
                    f"status={status} last_progress_age={age_text} progress={progress}"
                )

                if status in self.TERMINAL_STATUSES:
                    self._terminate_process(process)
                    return {
                        "stuck": False,
                        "timed_out": False,
                        "reason": f"Step reached terminal status '{status}'",
                        "terminal_status": status,
                    }

                stale_for = progress_age if progress_age is not None else time.monotonic() - started
                if stale_for >= self._stuck_timeout_seconds:
                    reason = (
                        f"No progress update for {int(stale_for)}s "
                        f"(stuck timeout {self._stuck_timeout_seconds}s)"
                    )
                    self._terminate_process(process)
                    return {
                        "stuck": True,
                        "timed_out": False,
                        "reason": reason,
                        "terminal_status": None,
                    }

    def _terminate_process(self, process: subprocess.Popen):
        if process.poll() is not None:
            return

        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (AttributeError, ProcessLookupError, PermissionError):
            process.terminate()

        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass

        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (AttributeError, ProcessLookupError, PermissionError):
            process.kill()
        process.wait()

    def _current_step_snapshot(self, step_num: int) -> dict:
        try:
            index = self._read_json(self._index_file)
        except (OSError, json.JSONDecodeError) as exc:
            return {"status": "unknown", "progress_message": f"status read failed: {exc}"}

        return next((dict(s) for s in index.get("steps", []) if s.get("step") == step_num), {})

    def _progress_age_seconds(self, step: dict) -> Optional[float]:
        progress_at = step.get("last_progress_at") or step.get("started_at")
        parsed = self._parse_stamp(progress_at)
        if parsed is None:
            return None
        return max(0.0, (datetime.now(self.TZ) - parsed).total_seconds())

    def _clear_running_fields(self, step: dict):
        step.pop("attempt", None)
        step.pop("last_progress_at", None)
        step.pop("progress_message", None)

    def _mark_step_running(self, step_num: int, attempt: int):
        index = self._read_json(self._index_file)
        for s in index["steps"]:
            if s["step"] == step_num:
                s["status"] = "running"
                s["attempt"] = attempt
                s["last_progress_at"] = self._stamp()
                s["progress_message"] = f"attempt {attempt} started"
                s.pop("error_message", None)
                break
        self._write_json(self._index_file, index)

    def _mark_step_error(self, step_num: int, error_message: str):
        index = self._read_json(self._index_file)
        for s in index["steps"]:
            if s["step"] == step_num:
                s["status"] = "error"
                s["error_message"] = error_message
                break
        self._write_json(self._index_file, index)

    def _recover_running_steps(self):
        index = self._read_json(self._index_file)
        changed = False
        for s in index["steps"]:
            if s.get("status") == "running":
                s["status"] = "pending"
                self._clear_running_fields(s)
                s.pop("error_message", None)
                changed = True
        if changed:
            self._write_json(self._index_file, index)

    # --- 헤더 & 검증 ---

    def _print_header(self):
        print(f"\n{'='*60}")
        print(f"  Harness Step Executor")
        print(f"  Phase: {self._phase_name} | Steps: {self._total}")
        if self._auto_push:
            print(f"  Auto-push: enabled")
        print(f"{'='*60}")

    def _check_blockers(self):
        index = self._read_json(self._index_file)
        for s in reversed(index["steps"]):
            if s["status"] == "error":
                print(f"\n  ✗ Step {s['step']} ({s['name']}) failed.")
                print(f"  Error: {s.get('error_message', 'unknown')}")
                print(f"  Fix and reset status to 'pending' to retry.")
                sys.exit(1)
            if s["status"] == "blocked":
                print(f"\n  ⏸ Step {s['step']} ({s['name']}) blocked.")
                print(f"  Reason: {s.get('blocked_reason', 'unknown')}")
                print(f"  Resolve and reset status to 'pending' to retry.")
                sys.exit(2)
            if s["status"] != "pending":
                break

    def _ensure_created_at(self):
        index = self._read_json(self._index_file)
        if "created_at" not in index:
            index["created_at"] = self._stamp()
            self._write_json(self._index_file, index)

    # --- 실행 루프 ---

    def _execute_single_step(self, step: dict, guardrails: str) -> bool:
        """단일 step 실행 (재시도 포함). 완료되면 True, 실패/차단이면 False."""
        step_num, step_name = step["step"], step["name"]
        done = sum(1 for s in self._read_json(self._index_file)["steps"] if s["status"] == "completed")
        prev_error = None

        for attempt in range(1, self.MAX_RETRIES + 1):
            index = self._read_json(self._index_file)
            step_context = self._build_step_context(index)
            preamble = self._build_preamble(guardrails, step_context, prev_error)

            tag = f"Step {step_num}/{self._total - 1} ({done} done): {step_name}"
            if attempt > 1:
                tag += f" [retry {attempt}/{self.MAX_RETRIES}]"

            self._mark_step_running(step_num, attempt)
            with progress_indicator(tag) as pi:
                self._invoke_codex(step, preamble)

            elapsed = int(pi.elapsed)

            index = self._read_json(self._index_file)
            status = next((s.get("status", "pending") for s in index["steps"] if s["step"] == step_num), "pending")
            ts = self._stamp()

            if status == "completed":
                for s in index["steps"]:
                    if s["step"] == step_num:
                        self._clear_running_fields(s)
                        s["completed_at"] = ts
                self._write_json(self._index_file, index)
                self._commit_step(step_num, step_name)
                print(f"  ✓ Step {step_num}: {step_name} [{elapsed}s]")
                return True

            if status == "blocked":
                for s in index["steps"]:
                    if s["step"] == step_num:
                        self._clear_running_fields(s)
                        s["blocked_at"] = ts
                self._write_json(self._index_file, index)
                reason = next((s.get("blocked_reason", "") for s in index["steps"] if s["step"] == step_num), "")
                print(f"  ⏸ Step {step_num}: {step_name} blocked [{elapsed}s]")
                print(f"    Reason: {reason}")
                self._update_top_index("blocked")
                sys.exit(2)

            err_msg = next(
                (s.get("error_message", "Step did not update status") for s in index["steps"] if s["step"] == step_num),
                "Step did not update status",
            )

            if attempt < self.MAX_RETRIES:
                for s in index["steps"]:
                    if s["step"] == step_num:
                        s["status"] = "pending"
                        s.pop("error_message", None)
                        self._clear_running_fields(s)
                self._write_json(self._index_file, index)
                prev_error = err_msg
                print(f"  ↻ Step {step_num}: retry {attempt}/{self.MAX_RETRIES} — {err_msg}")
            else:
                for s in index["steps"]:
                    if s["step"] == step_num:
                        s["status"] = "error"
                        s["error_message"] = f"[{self.MAX_RETRIES}회 시도 후 실패] {err_msg}"
                        self._clear_running_fields(s)
                        s["failed_at"] = ts
                self._write_json(self._index_file, index)
                self._commit_step(step_num, step_name)
                print(f"  ✗ Step {step_num}: {step_name} failed after {self.MAX_RETRIES} attempts [{elapsed}s]")
                print(f"    Error: {err_msg}")
                self._update_top_index("error")
                sys.exit(1)

        return False  # unreachable

    def _execute_all_steps(self, guardrails: str):
        while True:
            index = self._read_json(self._index_file)
            pending = next((s for s in index["steps"] if s["status"] == "pending"), None)
            if pending is None:
                print("\n  All steps completed!")
                return

            step_num = pending["step"]
            for s in index["steps"]:
                if s["step"] == step_num and "started_at" not in s:
                    s["started_at"] = self._stamp()
                    self._write_json(self._index_file, index)
                    break

            self._execute_single_step(pending, guardrails)

    def _finalize(self):
        index = self._read_json(self._index_file)
        index["completed_at"] = self._stamp()
        self._write_json(self._index_file, index)
        self._update_top_index("completed")

        self._run_git("add", "-A")
        if self._run_git("diff", "--cached", "--quiet").returncode != 0:
            msg = f"chore({self._phase_name}): mark phase completed"
            r = self._run_git("commit", "-m", msg)
            if r.returncode == 0:
                print(f"  ✓ {msg}")

        if self._auto_push:
            branch = f"feat-{self._phase_name}"
            r = self._run_git("push", "-u", "origin", branch)
            if r.returncode != 0:
                print(f"\n  ERROR: git push 실패: {r.stderr.strip()}")
                sys.exit(1)
            print(f"  ✓ Pushed to origin/{branch}")

        print(f"\n{'='*60}")
        print(f"  Phase '{self._phase_name}' completed!")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="Harness Step Executor")
    parser.add_argument("phase_dir", help="Phase directory name (e.g. 0-mvp)")
    parser.add_argument("--push", action="store_true", help="Push branch after completion")
    parser.add_argument(
        "--status-interval",
        type=int,
        default=StepExecutor.STATUS_POLL_INTERVAL_SECONDS,
        help="Seconds between status checks while Codex is running",
    )
    parser.add_argument(
        "--stuck-timeout",
        type=int,
        default=StepExecutor.STUCK_TIMEOUT_SECONDS,
        help="Seconds without last_progress_at updates before restarting a worker",
    )
    args = parser.parse_args()

    if args.status_interval <= 0:
        print("ERROR: --status-interval must be greater than 0")
        sys.exit(2)
    if args.stuck_timeout < 0:
        print("ERROR: --stuck-timeout must be 0 or greater")
        sys.exit(2)

    StepExecutor(
        args.phase_dir,
        auto_push=args.push,
        status_interval_seconds=args.status_interval,
        stuck_timeout_seconds=args.stuck_timeout,
    ).run()


if __name__ == "__main__":
    main()
