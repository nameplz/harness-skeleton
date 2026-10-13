import json
import hashlib
from pathlib import Path
import unittest

from evals.native_turn import TurnCollector

THREAD = "11111111-1111-4111-8111-111111111111"
TURN = "22222222-2222-4222-8222-222222222222"
PROMPT = "Fix the fixture."
ROOT = Path("/isolated/candidate")


def event(method, **params):
    return {"method": method, "params": {"threadId": THREAD, **params}}


def turn(status="inProgress", **extra):
    return {"id": TURN, "status": status, "items": [], **extra}


def command(status="inProgress", **extra):
    return {"id": "cmd1", "type": "commandExecution", "command": "python -m unittest discover", "cwd": str(ROOT), "commandActions": [], "status": status, **extra}


def usage():
    return {"last": {"inputTokens": 10, "cachedInputTokens": 3, "outputTokens": 5, "reasoningOutputTokens": 1, "totalTokens": 15}, "total": {"inputTokens": 10, "cachedInputTokens": 3, "outputTokens": 5, "reasoningOutputTokens": 1, "totalTokens": 15}}


class NativeTurnTests(unittest.TestCase):
    def ready(self):
        c = TurnCollector(THREAD, ROOT, PROMPT)
        c.notification(event("turn/started", turn=turn()))
        c.bind_response({"turn": turn()})
        item = {"id": "user1", "type": "userMessage", "content": [{"type": "text", "text": PROMPT, "text_elements": []}]}
        c.notification(event("item/started", turnId=TURN, item=item, startedAtMs=1))
        c.notification(event("item/completed", turnId=TURN, item=item, completedAtMs=2))
        return c

    def complete(self, c, status="completed", **extra):
        c.notification(event("turn/completed", turn=turn(status, **extra)))
        return c.result()

    def test_failed_and_declined_commands_are_retained(self):
        for status, code in (("completed", 0), ("failed", 1), ("declined", None)):
            with self.subTest(status=status):
                c = self.ready()
                c.notification(event("item/started", turnId=TURN, item=command(), startedAtMs=3))
                c.notification(event("item/completed", turnId=TURN, item=command(status, exitCode=code, aggregatedOutput="observed"), completedAtMs=4))
                c.notification(event("thread/tokenUsage/updated", turnId=TURN, tokenUsage=usage()))
                r = self.complete(c)
                self.assertEqual(status, r.actions[0].status)
                self.assertEqual(code, r.actions[0].exit_code)
                self.assertEqual("observed", r.actions[0].output)
                self.assertEqual(15, r.token_usage.total_tokens)
                self.assertEqual(hashlib.sha256(PROMPT.encode()).hexdigest(), r.prompt_sha256)
                self.assertTrue(r.item_lifecycle_complete)

    def test_turn_failures_are_outcomes_not_success(self):
        for status in ("failed", "interrupted"):
            c = self.ready()
            c.notification(event("error", turnId=TURN, error={"message": "fixture failure"}, willRetry=False))
            r = self.complete(c, status, error={"message": "fixture failure"})
            self.assertEqual(status, r.status)
            self.assertEqual(1, r.error_count)
            self.assertIsNone(r.token_usage)

    def test_unknown_server_requests_and_capabilities_are_rejected(self):
        for method in ("mcpToolCall", "dynamicToolCall", "collabAgentToolCall", "webSearch", "imageGeneration"):
            c = self.ready()
            with self.subTest(method=method), self.assertRaises(ValueError):
                c.notification(event("item/started", turnId=TURN, item={"id": "bad", "type": method}, startedAtMs=3))
        for message in ({"id": 8, **event("item/commandExecution/requestApproval")}, event("mcpServer/startupStatus/updated"), event("model/rerouted", turnId=TURN)):
            with self.assertRaises(ValueError): self.ready().notification(message)

    def test_mixed_thread_turn_replay_or_duplicate_is_rejected(self):
        for change in ({"threadId": "other"}, {"turnId": "other"}):
            c = self.ready(); message = event("item/started", turnId=TURN, item=command(), startedAtMs=3)
            message["params"].update(change)
            with self.assertRaises(ValueError): c.notification(message)
        c = self.ready()
        with self.assertRaises(ValueError): c.bind_response({"turn": turn()})
        with self.assertRaises(ValueError): c.notification(event("turn/started", turn=turn()))

    def test_missing_user_input_completion_or_item_lifecycle_is_rejected(self):
        c = TurnCollector(THREAD, ROOT, PROMPT); c.bind_response({"turn": turn()}); c.notification(event("turn/started", turn=turn()))
        with self.assertRaises(ValueError): self.complete(c)
        c = self.ready()
        with self.assertRaises(ValueError): c.result()
        with self.assertRaises(ValueError): c.notification(event("item/completed", turnId=TURN, item=command("completed", exitCode=0), completedAtMs=4))
        c = self.ready(); c.notification(event("item/started", turnId=TURN, item=command(), startedAtMs=3))
        with self.assertRaises(ValueError): self.complete(c)

    def test_prompt_mismatch_and_changed_command_are_rejected(self):
        c = self.ready()
        bad = {"id": "user2", "type": "userMessage", "content": [{"type": "text", "text": "different"}]}
        with self.assertRaises(ValueError): c.notification(event("item/started", turnId=TURN, item=bad, startedAtMs=3))
        c = self.ready(); c.notification(event("item/started", turnId=TURN, item=command(), startedAtMs=3))
        with self.assertRaises(ValueError): c.notification(event("item/completed", turnId=TURN, item=command("completed", command="other", exitCode=0), completedAtMs=4))

    def test_late_tool_event_rejected_but_late_usage_retained(self):
        c = self.ready(); self.complete(c)
        c.notification(event("thread/tokenUsage/updated", turnId=TURN, tokenUsage=usage()))
        self.assertEqual(15, c.result().token_usage.total_tokens)
        with self.assertRaises(ValueError): c.notification(event("item/started", turnId=TURN, item=command(), startedAtMs=5))
        with self.assertRaises(ValueError): self.complete(c)

    def test_invalid_usage_status_output_and_timestamp_are_rejected(self):
        for token in (-1, True, "12"):
            c = self.ready(); u = usage(); u["total"]["inputTokens"] = token
            with self.assertRaises(ValueError): c.notification(event("thread/tokenUsage/updated", turnId=TURN, tokenUsage=u))
        for changes in ({"status": "unknown"}, {"pluginId": "plugin"}, {"cwd": "/outside"}):
            with self.assertRaises(ValueError): self.ready().notification(event("item/started", turnId=TURN, item=command(**changes), startedAtMs=3))
        c = self.ready(); c.notification(event("item/started", turnId=TURN, item=command(), startedAtMs=3))
        with self.assertRaises(ValueError): c.notification(event("item/completed", turnId=TURN, item=command("completed", exitCode=True), completedAtMs=4))
        with self.assertRaises(ValueError): self.ready().notification(event("item/started", turnId=TURN, item=command(), startedAtMs=True))

    def test_delta_must_match_started_item(self):
        c = self.ready()
        item = {"id": "a1", "type": "agentMessage", "text": ""}
        c.notification(event("item/started", turnId=TURN, item=item, startedAtMs=3))
        c.notification(event("item/agentMessage/delta", turnId=TURN, itemId="a1", delta="fixed"))
        c.notification(event("item/completed", turnId=TURN, item={**item, "text": "fixed"}, completedAtMs=4))
        self.assertEqual(("fixed",), self.complete(c).assistant_messages)

    def test_file_change_status_is_retained(self):
        c = self.ready(); item = {"id": "p1", "type": "fileChange", "changes": [{"path": str(ROOT / "calc.py"), "kind": {"type": "update", "move_path": None}, "diff": "diff"}], "status": "inProgress"}
        c.notification(event("item/started", turnId=TURN, item=item, startedAtMs=3))
        c.notification(event("item/completed", turnId=TURN, item={**item, "status": "declined"}, completedAtMs=4))
        r = self.complete(c)
        self.assertEqual("declined", r.actions[0].status)
        self.assertEqual((str(ROOT / "calc.py"),), r.actions[0].paths)

    def test_events_are_raw_rpc_records_without_cli_conversion(self):
        c = self.ready(); r = self.complete(c)
        self.assertEqual("turn/started", json.loads(r.events_json[0])["method"])
        self.assertFalse(any("type" in json.loads(row) for row in r.events_json))
        self.assertFalse(r.os_action_audit_complete)

    def test_rejection_permanently_invalidates_collector(self):
        c = self.ready()
        with self.assertRaises(ValueError): c.notification(event("unexpected", turnId=TURN))
        with self.assertRaises(ValueError): self.complete(c)
        with self.assertRaises(ValueError): c.result()

    def test_summary_cannot_hide_unobserved_items(self):
        c = self.ready()
        with self.assertRaises(ValueError): self.complete(c, items=[command("completed", exitCode=0)])

    def test_event_limit_and_invalid_initial_input_are_rejected(self):
        c = self.ready(); c.event_bytes = 1024 * 1024
        with self.assertRaises(ValueError): c.notification(event("thread/tokenUsage/updated", turnId=TURN, tokenUsage=usage()))
        for args in (("other", ROOT, PROMPT), (THREAD, Path("relative"), PROMPT), (THREAD, ROOT, "")):
            with self.assertRaises(ValueError): TurnCollector(*args)

    def test_usage_cannot_decrease_or_exceed_cumulative_total(self):
        c = self.ready(); c.notification(event("thread/tokenUsage/updated", turnId=TURN, tokenUsage=usage()))
        u = usage(); u["total"]["inputTokens"] = 0
        with self.assertRaises(ValueError): c.notification(event("thread/tokenUsage/updated", turnId=TURN, tokenUsage=u))

    def test_completed_summary_is_subset_of_streamed_items(self):
        c = self.ready(); item = {"id": "a1", "type": "agentMessage", "text": "done"}
        c.notification(event("item/started", turnId=TURN, item=item, startedAtMs=3))
        c.notification(event("item/completed", turnId=TURN, item=item, completedAtMs=4))
        r = self.complete(c, items=[item])
        self.assertEqual(("done",), r.assistant_messages)

    def test_raw_input_object_mutation_does_not_change_evidence(self):
        c = self.ready(); message = event("item/started", turnId=TURN, item=command(), startedAtMs=3)
        c.notification(message); message["params"]["item"]["command"] = "tampered"
        c.notification(event("item/completed", turnId=TURN, item=command("completed", exitCode=0), completedAtMs=4))
        r = self.complete(c)
        self.assertEqual("python -m unittest discover", r.actions[0].command)
        self.assertNotIn("tampered", str(r.events_json))

    def test_malformed_response_poisoning_is_permanent(self):
        c = TurnCollector(THREAD, ROOT, PROMPT)
        with self.assertRaises(ValueError): c.bind_response({"turn": turn(status=[])})
        with self.assertRaises(ValueError): c.bind_response({"turn": turn()})

    def test_invalid_unicode_input_fails_closed(self):
        c = self.ready(); bad = command(); bad["command"] = "\ud800"
        with self.assertRaises(ValueError): c.notification(event("item/started", turnId=TURN, item=bad, startedAtMs=3))
        with self.assertRaises(ValueError): self.complete(c)
