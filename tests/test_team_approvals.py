import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


TOOLS_PATH = Path(__file__).resolve().parents[1] / "tools.py"
SPEC = importlib.util.spec_from_file_location("direct_agent_api_tools_under_test", TOOLS_PATH)
tools = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = tools
SPEC.loader.exec_module(tools)


class TeamApprovalQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.routes = root / "routes.json"
        self.db = root / "approvals.db"
        self.routes.write_text(json.dumps({
            "profiles": {
                "default": {
                    "endpoint": "http://127.0.0.1:9661",
                    "api_key": "jarvis-test-secret-not-returned",
                    "allowed_targets": ["delivery"],
                },
                "delivery": {
                    "endpoint": "http://127.0.0.1:9999",
                    "api_key": "test-secret-not-returned",
                },
            },
        }))
        self.routes.chmod(0o600)
        self.path_patch = patch.multiple(
            tools,
            ROUTES_PATH=self.routes,
            APPROVAL_DB_PATH=self.db,
        )
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)

    def test_coordinate_agent_queues_formal_correlated_approval(self):
        calls = []

        def fake_request(url, key, method, body=None):
            calls.append((url, method, body))
            if method == "POST":
                return {"run_id": "run_123", "status": "started"}
            return {
                "run_id": "run_123",
                "status": "waiting_for_approval",
                "pending_approvals": [{
                    "request_id": "apr_123",
                    "run_id": "run_123",
                    "command": "docker run postgres",
                    "description": "container execution",
                    "pattern_keys": ["container-exec"],
                    "choices": ["once", "deny"],
                }],
            }

        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", side_effect=fake_request):
            result = json.loads(tools.coordinate_agent({
                "target": "delivery",
                "objective": "Run the isolated PostgreSQL integration tests",
                "context": "No production systems.",
                "wait_seconds": 1,
            }))

        self.assertFalse(result["ok"])
        self.assertTrue(result["requires_approval"])
        self.assertEqual(result["approval"]["request_id"], "apr_123")
        self.assertEqual(result["approval"]["requesting_profile"], "delivery")
        self.assertNotIn("test-secret-not-returned", json.dumps(result))

        with patch.object(tools, "_profile_name", return_value="default"):
            pending = json.loads(tools.list_team_approvals({}))
        self.assertEqual(pending["count"], 1)
        self.assertEqual(pending["approvals"][0]["paused_run_id"], "run_123")
        self.assertEqual(pending["approvals"][0]["status"], "pending")

    def test_jarvis_allow_once_delivers_correlated_decision_and_consumes_once(self):
        tools._init_approval_db()
        now = time.time()
        tools._store_approval({
            "request_id": "apr_allow",
            "trace_id": "a2a-default-delivery-test",
            "calling_profile": "default",
            "requesting_profile": "delivery",
            "paused_run_id": "run_allow",
            "requested_action": "Run safe tests",
            "tool": "terminal",
            "description": "container execution",
            "command_preview": "docker run --rm postgres",
            "risk_class": "internal-write",
            "created_at": now,
            "expires_at": now + 900,
        })
        delivered = []

        def fake_request(url, key, method, body=None, idempotency_key=None):
            delivered.append((url, method, body))
            return {
                "object": "hermes.run.approval_response",
                "run_id": "run_allow",
                "request_id": "apr_allow",
                "choice": "once",
                "resolved": 1,
            }

        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", side_effect=fake_request):
            result = json.loads(tools.respond_team_approval({
                "request_id": "apr_allow",
                "decision": "allow-once",
            }))

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "consumed")
        self.assertEqual(delivered[0][2], {
            "choice": "once",
            "request_id": "apr_allow",
        })

        with patch.object(tools, "_profile_name", return_value="default"):
            replay = json.loads(tools.respond_team_approval({
                "request_id": "apr_allow",
                "decision": "allow-once",
            }))
        self.assertFalse(replay["ok"])
        self.assertEqual(replay["error"], "approval is not pending")

    def test_specialist_cannot_resolve_queue(self):
        with patch.object(tools, "_profile_name", return_value="delivery"):
            listed = json.loads(tools.list_team_approvals({}))
            decided = json.loads(tools.respond_team_approval({
                "request_id": "apr_missing",
                "decision": "deny",
            }))
        self.assertEqual(listed["error"], "Jarvis approval router only")
        self.assertEqual(decided["error"], "Jarvis approval router only")

    def test_expired_request_fails_closed_without_api_call(self):
        tools._init_approval_db()
        now = time.time()
        tools._store_approval({
            "request_id": "apr_expired",
            "trace_id": "a2a-default-qa-expired",
            "calling_profile": "default",
            "requesting_profile": "qa",
            "paused_run_id": "run_expired",
            "requested_action": "Expired action",
            "tool": "terminal",
            "description": "expired",
            "command_preview": "true",
            "risk_class": "internal-read",
            "created_at": now - 1000,
            "expires_at": now - 1,
        })
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request") as request:
            result = json.loads(tools.respond_team_approval({
                "request_id": "apr_expired",
                "decision": "allow-once",
            }))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "approval expired")
        request.assert_not_called()


class DurableControlPlaneTests(TeamApprovalQueueTests):
    def _seed_run(self, **overrides):
        record = {
            "trace_id": "a2a-default-delivery-late", "calling_profile": "default",
            "target_profile": "delivery", "run_id": "run_late",
            "parent_session_id": "session_jarvis", "objective": "Run bounded internal tests",
            "created_at": time.time(),
        }
        record.update(overrides)
        return tools._store_coordination_run(record)

    def test_policy_classifies_staging_domains_without_creating_categorical_jan_gate(self):
        allowed = ("kobra.cloud", "api.kobra.cloud", "kobra-dataworks.de", "qa.kobra-dataworks.de")
        for domain in allowed:
            with self.subTest(domain=domain):
                risk, gated = tools._classify_approval("terminal", "staging deployment", f"deploy reversible staging to {domain}")
                self.assertEqual(risk, "company-staging-deploy")
                self.assertFalse(gated)
        for domain in ("evilkobra.cloud", "kobra.cloud.example.com", "customer-example.de"):
            with self.subTest(domain=domain):
                risk, gated = tools._classify_approval("terminal", "staging deployment", f"deploy reversible staging to {domain}")
                self.assertEqual(risk, "customer-or-lookalike-domain")
                self.assertFalse(gated)

    def test_action_categories_are_controls_not_jan_gates_without_material_harm(self):
        cases = (
            ("messages_send", "active customer communication", "send email to customer"),
            ("terminal", "production deploy", "deploy reversible production release"),
            ("terminal", "credential rotation", "rotate scoped api key with rollback"),
            ("terminal", "destructive cleanup", "delete disposable synthetic fixture after backup"),
        )
        for tool, description, command in cases:
            with self.subTest(command=command):
                risk, gated = tools._classify_approval(tool, description, command)
                self.assertNotEqual(risk, "material-harm")
                self.assertFalse(gated)

    def test_explicit_credible_material_harm_is_the_only_jan_gate(self):
        risk, gated = tools._classify_approval(
            "terminal",
            "credible material harm: irreversible customer data loss",
            "drop production customer data without backup or rollback",
        )
        self.assertEqual(risk, "material-harm")
        self.assertTrue(gated)

    def test_goal_mandate_migration_is_additive_and_historical_rows_are_unchanged(self):
        with tools._db_connect() as conn:
            conn.executescript("""
                CREATE TABLE approval_request (
                    request_id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, calling_profile TEXT NOT NULL,
                    requesting_profile TEXT NOT NULL, paused_run_id TEXT NOT NULL, requested_action TEXT NOT NULL,
                    tool TEXT NOT NULL, description TEXT NOT NULL, command_preview TEXT NOT NULL,
                    command_sha256 TEXT NOT NULL, risk_class TEXT NOT NULL,
                    requires_jan INTEGER NOT NULL CHECK (requires_jan IN (0,1)), status TEXT NOT NULL,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL, decided_at REAL, decision TEXT,
                    decision_actor TEXT, consumed_at REAL,
                    UNIQUE(requesting_profile, paused_run_id, request_id)
                );
                INSERT INTO approval_request VALUES(
                    'apr_history','trace','default','delivery','run_history','old','terminal','old','true',
                    'sha','internal-read',0,'consumed',1,2,2,'allow-once','jarvis',2
                );
            """)
        tools._init_approval_db()
        with tools._db_connect() as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(approval_request)")}
            history = tuple(conn.execute(
                "SELECT request_id,status,decision,requires_jan FROM approval_request WHERE request_id='apr_history'"
            ).fetchone())
            mandate_table = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='goal_mandate'"
            ).fetchone()[0]
        self.assertTrue({"goal_mandate_id", "scope_fingerprint"} <= columns)
        self.assertEqual(history, ("apr_history", "consumed", "allow-once", 0))
        self.assertEqual(mandate_table, 1)

    def test_active_goal_mandate_is_persistent_and_readable(self):
        record = tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        reread = tools.get_active_goal_mandate("gm_kobra_operating_authority_20260725")
        self.assertEqual(record["mandate_id"], "gm_kobra_operating_authority_20260725")
        self.assertEqual(reread["status"], "active")
        self.assertEqual(len(reread["scope_fingerprint"]), 64)
        self.assertEqual(reread["decision_evidence"], "Jan Telegram 2026-07-25")

    def test_equivalent_safe_requests_auto_resolve_without_jarvis_notification(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        now = time.time()
        delivered = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            delivered.append((url, method, body, idempotency_key))
            return {"run_id": body["request_id"].replace("apr_", "run_"),
                    "request_id": body["request_id"], "choice": "once", "resolved": 1}
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", side_effect=fake_request):
            for suffix in ("one", "two"):
                run_id = f"run_{suffix}"
                request_id = f"apr_{suffix}"
                self._seed_run(run_id=run_id)
                row = tools._store_approval({
                    "request_id": request_id, "trace_id": f"trace_{suffix}", "calling_profile": "default",
                    "requesting_profile": "delivery", "paused_run_id": run_id,
                    "requested_action": "Run the same bounded safe test", "tool": "terminal",
                    "description": "bounded internal test", "command_preview": "python -m unittest safe_test",
                    "created_at": now, "expires_at": now + 900,
                })
                result = tools._auto_resolve_if_covered(row)
                self.assertTrue(result["ok"])
        self.assertEqual(len(delivered), 2)
        with tools._db_connect() as conn:
            rows = conn.execute(
                "SELECT status,goal_mandate_id,scope_fingerprint,notification_state FROM approval_request ORDER BY request_id"
            ).fetchall()
        self.assertTrue(all(row[0] == "consumed" for row in rows))
        self.assertTrue(all(row[1] == "gm_kobra_operating_authority_20260725" for row in rows))
        self.assertEqual(len({row[2] for row in rows}), 1)
        self.assertTrue(all(row[3] == "suppressed_by_mandate" for row in rows))

    def test_equivalent_material_harm_requests_share_one_current_route_and_packet(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        now = time.time()
        self._seed_run(run_id="run_harm_one")
        self._seed_run(run_id="run_harm_two")
        records = []
        for request_id, run_id in (("apr_harm_one", "run_harm_one"), ("apr_harm_two", "run_harm_two")):
            records.append(tools._store_approval({
                "request_id": request_id, "trace_id": f"trace_{request_id}", "calling_profile": "default",
                "requesting_profile": "delivery", "paused_run_id": run_id,
                "requested_action": "Drop production database", "tool": "terminal",
                "description": "credible material harm: irreversible customer data loss",
                "command_preview": "DROP DATABASE production", "created_at": now, "expires_at": now + 900,
            }))
        self.assertEqual(records[0]["request_id"], "apr_harm_one")
        self.assertEqual(records[1]["request_id"], "apr_harm_two")
        self.assertEqual(records[0]["canonical_request_id"], "apr_harm_one")
        self.assertEqual(records[1]["canonical_request_id"], "apr_harm_one")
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", return_value={"run_id": "jarvis_notice", "status": "started"}) as request:
            self.assertTrue(tools._notify_jarvis(records[0], now))
            self.assertFalse(tools._notify_jarvis(records[1], now + 1))
            packet = json.loads(tools.respond_team_approval({"request_id": "apr_harm_one", "decision": "escalate-to-Jan"}))
            replay = json.loads(tools.respond_team_approval({"request_id": "apr_harm_two", "decision": "escalate-to-Jan"}))
        request.assert_called_once()
        self.assertEqual(packet["decision_packet"]["request_id"], "apr_harm_one")
        self.assertEqual(replay["error"], "approval is not pending")
        with tools._db_connect() as conn:
            request_count = conn.execute("SELECT COUNT(*) FROM approval_request").fetchone()[0]
            linked = conn.execute(
                "SELECT canonical_request_id,paused_run_id,status,notification_state FROM approval_request WHERE request_id='apr_harm_two'"
            ).fetchone()
            requested_count = conn.execute(
                "SELECT COUNT(*) FROM approval_event WHERE event_type='requested'"
            ).fetchone()[0]
            routed_count = conn.execute(
                "SELECT COUNT(*) FROM approval_event WHERE event_type='routed_to_jarvis'"
            ).fetchone()[0]
        self.assertEqual(request_count, 2)
        self.assertEqual(tuple(linked), ("apr_harm_one", "run_harm_two", "escalated", "linked_to_canonical"))
        self.assertEqual(requested_count, 2)
        self.assertEqual(routed_count, 1)

    def test_reusable_decision_fans_out_to_each_exact_native_request_and_run_once(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        now = time.time()
        for request_id, run_id in (("apr_fanout_one", "run_fanout_one"), ("apr_fanout_two", "run_fanout_two")):
            self._seed_run(run_id=run_id)
            tools._store_approval({
                "request_id": request_id, "trace_id": f"trace_{request_id}", "calling_profile": "default",
                "requesting_profile": "delivery", "paused_run_id": run_id,
                "requested_action": "Deploy the same reversible production release", "tool": "terminal",
                "description": "production deploy with rollback", "command_preview": "deploy release artifact-123",
                "created_at": now, "expires_at": now + 900,
            })
        calls = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            calls.append((url, method, dict(body or {}), idempotency_key))
            return {"run_id": url.split("/")[-2], "request_id": body["request_id"],
                    "choice": body["choice"], "resolved": 1}
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", side_effect=fake_request):
            result = json.loads(tools.respond_team_approval({"request_id": "apr_fanout_one", "decision": "allow-once"}))
            replay = json.loads(tools.respond_team_approval({"request_id": "apr_fanout_two", "decision": "allow-once"}))
        self.assertTrue(result["ok"])
        self.assertEqual(result["delivered_request_ids"], ["apr_fanout_one", "apr_fanout_two"])
        self.assertEqual([(call[0], call[2]["request_id"]) for call in calls], [
            ("http://127.0.0.1:9999/v1/runs/run_fanout_one/approval", "apr_fanout_one"),
            ("http://127.0.0.1:9999/v1/runs/run_fanout_two/approval", "apr_fanout_two"),
        ])
        self.assertTrue(all(call[3] == f"approval-decision-{call[2]['request_id']}" for call in calls))
        self.assertFalse(replay["ok"])
        self.assertEqual(len(calls), 2)
        with tools._db_connect() as conn:
            rows = conn.execute(
                "SELECT request_id,paused_run_id,status,resume_state FROM approval_request WHERE canonical_request_id='apr_fanout_one' ORDER BY request_id"
            ).fetchall()
            resumes = conn.execute(
                "SELECT run_id,resume_state FROM coordination_run WHERE run_id LIKE 'run_fanout_%' ORDER BY run_id"
            ).fetchall()
        self.assertEqual([tuple(row) for row in rows], [
            ("apr_fanout_one", "run_fanout_one", "consumed", "resumed"),
            ("apr_fanout_two", "run_fanout_two", "consumed", "resumed"),
        ])
        self.assertEqual([tuple(row) for row in resumes], [
            ("run_fanout_one", "resumed"), ("run_fanout_two", "resumed")
        ])

    def test_scope_admission_is_atomic_but_preserves_both_native_request_rows(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        now = time.time()
        barrier = threading.Barrier(2)
        results, errors = [], []
        def store(request_id, run_id):
            try:
                barrier.wait(timeout=2)
                results.append(tools._store_approval({
                    "request_id": request_id, "trace_id": f"trace_{request_id}", "calling_profile": "default",
                    "requesting_profile": "delivery", "paused_run_id": run_id,
                    "requested_action": "Drop production database", "tool": "terminal",
                    "description": "credible material harm: irreversible customer data loss",
                    "command_preview": "DROP DATABASE production", "created_at": now, "expires_at": now + 900,
                }))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=store, args=(f"apr_atomic_{n}", f"run_atomic_{n}")) for n in (1, 2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=5)
        self.assertFalse(errors)
        with tools._db_connect() as conn:
            rows = conn.execute(
                "SELECT request_id,canonical_request_id,notification_state FROM approval_request ORDER BY request_id"
            ).fetchall()
            scopes = conn.execute("SELECT canonical_request_id FROM approval_scope_current").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(scopes), 1)
        canonical = scopes[0][0]
        self.assertEqual({row[1] for row in rows}, {canonical})
        self.assertEqual(sum(row[2] != "linked_to_canonical" for row in rows), 1)

    def test_final_result_delivery_updates_approval_state_and_audits_transactionally(self):
        self._seed_run(run_id="run_final")
        now = time.time()
        tools._store_approval({
            "request_id": "apr_final", "trace_id": "trace_final", "calling_profile": "default",
            "requesting_profile": "delivery", "paused_run_id": "run_final",
            "requested_action": "Run safe tests", "tool": "terminal", "description": "bounded internal tests",
            "command_preview": "python -m unittest", "created_at": now, "expires_at": now + 900,
        })
        with patch.object(tools, "_request", return_value={"run_id": "jarvis_final", "status": "started"}):
            delivered = tools._deliver_final_result({
                "run_id": "run_final", "trace_id": "trace_final", "target_profile": "delivery",
                "parent_session_id": "session_jarvis",
            }, "completed", "verified result", now)
        self.assertTrue(delivered)
        with tools._db_connect() as conn:
            run_state = conn.execute(
                "SELECT final_delivery_state FROM coordination_run WHERE run_id='run_final'"
            ).fetchone()[0]
            approval_state = conn.execute(
                "SELECT final_result_delivery_state FROM approval_request WHERE request_id='apr_final'"
            ).fetchone()[0]
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM approval_event WHERE request_id='apr_final' AND event_type='final_result_delivered_to_jarvis'"
            ).fetchone()[0]
        self.assertEqual(run_state, "delivered")
        self.assertEqual(approval_state, "delivered")
        self.assertEqual(audit_count, 1)

    def test_queue_uses_redacted_command_preview_and_notification_carries_it(self):
        self._seed_run()
        waiting = {"run_id": "run_late", "status": "waiting_for_approval", "pending_approvals": [{
            "request_id": "apr_preview", "run_id": "run_late",
            "command_preview": "python3 -m pytest tests/test_contract.py -q",
            "description": "bounded internal tests", "pattern_keys": ["terminal"],
        }]}
        row = tools._queue_from_status(
            latest=waiting, trace_id="trace_preview", caller="default",
            target="developer136", objective="Run bounded tests",
        )
        self.assertEqual(row["command_preview"], "python3 -m pytest tests/test_contract.py -q")
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", return_value={"run_id": "jarvis_notice", "status": "started"}) as request:
            self.assertTrue(tools._notify_jarvis(row, time.time()))
        prompt = request.call_args.args[3]["input"]
        self.assertIn("command_preview: python3 -m pytest tests/test_contract.py -q", prompt)

    def test_late_waiting_run_is_discovered_notified_once_and_survives_restart(self):
        self._seed_run()
        waiting = {"run_id": "run_late", "status": "waiting_for_approval", "pending_approvals": [{
            "request_id": "apr_late", "run_id": "run_late", "command": "python -m unittest",
            "description": "bounded internal tests", "pattern_keys": ["terminal"],
        }]}
        calls = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            calls.append((url, method, body, idempotency_key))
            if url.endswith("/v1/runs/run_late"): return waiting
            if url.endswith("/v1/runs"): return {"run_id": "jarvis_notice", "status": "started"}
            raise AssertionError(url)
        with patch.object(tools, "_request", side_effect=fake_request):
            first = tools._reconcile_once(now=time.time())
            second = tools._reconcile_once(now=time.time() + 1)
        self.assertEqual(first["approvals_discovered"], 1)
        self.assertEqual(first["notifications_delivered"], 1)
        self.assertEqual(second["notifications_delivered"], 0)
        notices = [c for c in calls if c[0].endswith("/v1/runs")]
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0][3], "approval-notify-apr_late")
        with tools._db_connect() as conn:
            approval = conn.execute("SELECT * FROM approval_request WHERE request_id='apr_late'").fetchone()
            run = conn.execute("SELECT * FROM coordination_run WHERE run_id='run_late'").fetchone()
        self.assertEqual(approval["notification_state"], "delivered")
        self.assertEqual(run["parent_session_id"], "session_jarvis")
        self.assertEqual(run["resume_state"], "waiting_for_decision")

    def test_allow_once_resumes_exact_run_then_returns_final_result_to_jarvis(self):
        self._seed_run(run_id="run_resume")
        now = time.time()
        tools._store_approval({"request_id": "apr_resume", "trace_id": "a2a-default-delivery-late",
            "calling_profile": "default", "requesting_profile": "delivery", "paused_run_id": "run_resume",
            "parent_session_id": "session_jarvis", "requested_action": "Run safe tests", "tool": "terminal",
            "description": "bounded internal tests", "command_preview": "python -m unittest",
            "risk_class": "internal-write", "created_at": now, "expires_at": now + 900})
        calls = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            calls.append((url, method, body, idempotency_key))
            if url.endswith("/v1/runs/run_resume/approval"): return {"run_id": "run_resume", "request_id": "apr_resume", "choice": "once", "resolved": 1}
            if url.endswith("/v1/runs/run_resume"): return {"run_id": "run_resume", "status": "completed", "output": "verified result"}
            if url.endswith("/v1/runs"): return {"run_id": "jarvis_result", "status": "started"}
            raise AssertionError(url)
        with patch.object(tools, "_profile_name", return_value="default"), patch.object(tools, "_request", side_effect=fake_request):
            decision = json.loads(tools.respond_team_approval({"request_id": "apr_resume", "decision": "allow-once"}))
            reconciled = tools._reconcile_once(now=time.time())
        self.assertTrue(decision["ok"])
        self.assertEqual(reconciled["final_results_delivered"], 1)
        approvals = [c for c in calls if c[0].endswith("/v1/runs/run_resume/approval")]
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0][2]["request_id"], "apr_resume")
        finals = [c for c in calls if c[0].endswith("/v1/runs")]
        self.assertEqual(len(finals), 1)
        self.assertEqual(finals[0][3], "final-result-run_resume")
        with tools._db_connect() as conn:
            run = conn.execute("SELECT * FROM coordination_run WHERE run_id='run_resume'").fetchone()
        self.assertEqual(run["resume_state"], "resumed")
        self.assertEqual(run["final_delivery_state"], "delivered")

    def test_escalation_returns_linked_decision_packet_without_resuming(self):
        now = time.time()
        tools._store_approval({"request_id": "apr_jan", "trace_id": "a2a-default-delivery-jan",
            "calling_profile": "default", "requesting_profile": "delivery", "paused_run_id": "run_jan",
            "requested_action": "Send customer email", "tool": "terminal", "description": "active customer communication",
            "command_preview": "send email to customer", "created_at": now, "expires_at": now + 900})
        with patch.object(tools, "_profile_name", return_value="default"), patch.object(tools, "_request") as request:
            result = json.loads(tools.respond_team_approval({"request_id": "apr_jan", "decision": "escalate-to-Jan"}))
        self.assertTrue(result["ok"])
        self.assertEqual(result["decision_packet"]["request_id"], "apr_jan")
        self.assertEqual(result["decision_packet"]["required_approval"], "Jan")
        request.assert_not_called()

    def test_catastrophic_commands_classify_as_material_harm(self):
        cases = (
            "rm -rf /home/jan/.hermes",
            "rm -rf /home/jan/.hermes/",
            "DROP DATABASE production",
            "drop database production;",
        )
        for command in cases:
            with self.subTest(command=command):
                risk, gated = tools._classify_approval("terminal", "covered maintenance", command)
                self.assertEqual(risk, "material-harm")
                self.assertTrue(gated)
                self.assertEqual(tools._approval_lane(risk, gated), "material-harm")

    def test_bounded_temp_delete_requires_internal_jarvis_review_not_jan(self):
        risk, gated = tools._classify_approval(
            "terminal", "bounded cleanup", "rm -rf /tmp/kobra-goal-mandate-canary-123"
        )
        self.assertEqual(risk, "destructive")
        self.assertFalse(gated)
        self.assertEqual(tools._approval_lane(risk, gated), "jarvis-review")

    def test_low_risk_covered_action_auto_resolves(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        self._seed_run(run_id="run_low")
        now = time.time()
        row = tools._store_approval({
            "request_id": "apr_low", "trace_id": "trace_low", "calling_profile": "default",
            "requesting_profile": "delivery", "paused_run_id": "run_low",
            "requested_action": "Run bounded unit test", "tool": "terminal",
            "description": "bounded internal test", "command_preview": "python -m unittest safe_test",
            "created_at": now, "expires_at": now + 900,
        })
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", return_value={
                 "run_id": "run_low", "request_id": "apr_low", "choice": "once", "resolved": 1,
             }) as request:
            result = tools._auto_resolve_if_covered(row)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "consumed")
        request.assert_called_once()

    def test_high_impact_covered_action_routes_to_jarvis_once_without_auto_resolution(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        self._seed_run(run_id="run_review")
        now = time.time()
        risk, gated = tools._classify_approval(
            "terminal", "bounded cleanup", "rm -rf /tmp/kobra-goal-mandate-canary-review"
        )
        row = tools._store_approval({
            "request_id": "apr_review", "trace_id": "trace_review", "calling_profile": "default",
            "requesting_profile": "delivery", "paused_run_id": "run_review",
            "requested_action": "Delete bounded temp canary", "tool": "terminal",
            "description": "bounded cleanup", "command_preview": "rm -rf /tmp/kobra-goal-mandate-canary-review",
            "risk_class": risk, "requires_jan": gated, "created_at": now, "expires_at": now + 900,
        })
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request", return_value={"run_id": "jarvis_review", "status": "started"}) as request:
            auto = tools._auto_resolve_if_covered(row)
            first = tools._notify_jarvis(row, now)
            second = tools._notify_jarvis(row, now + 1)
        self.assertFalse(auto["ok"])
        self.assertEqual(auto["lane"], "jarvis-review")
        self.assertTrue(first)
        self.assertFalse(second)
        request.assert_called_once()
        self.assertEqual(request.call_args.kwargs["idempotency_key"], "approval-notify-apr_review")

    def test_material_harm_is_blocked_and_yields_one_jan_decision_packet(self):
        tools.activate_goal_mandate(tools.CURRENT_GOAL_MANDATE)
        self._seed_run(run_id="run_harm")
        now = time.time()
        risk, gated = tools._classify_approval("terminal", "covered maintenance", "DROP DATABASE production")
        row = tools._store_approval({
            "request_id": "apr_harm", "trace_id": "trace_harm", "calling_profile": "default",
            "requesting_profile": "delivery", "paused_run_id": "run_harm",
            "requested_action": "Drop production database", "tool": "terminal",
            "description": "covered maintenance", "command_preview": "DROP DATABASE production",
            "risk_class": risk, "requires_jan": gated, "created_at": now, "expires_at": now + 900,
        })
        with patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools, "_request") as request:
            blocked = tools._auto_resolve_if_covered(row)
            forbidden = json.loads(tools.respond_team_approval({"request_id": "apr_harm", "decision": "allow-once"}))
            escalated = json.loads(tools.respond_team_approval({"request_id": "apr_harm", "decision": "escalate-to-Jan"}))
            replay = json.loads(tools.respond_team_approval({"request_id": "apr_harm", "decision": "escalate-to-Jan"}))
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["lane"], "material-harm")
        self.assertEqual(forbidden["error"], "approval requires Jan")
        self.assertEqual(escalated["status"], "escalated")
        self.assertEqual(escalated["decision_packet"]["required_approval"], "Jan")
        self.assertEqual(replay["error"], "approval is not pending")
        request.assert_not_called()

    def test_donna_agentsai_profile_has_jarvis_return_route(self):
        routes = json.loads(self.routes.read_text())
        routes["profiles"]["agentsai"] = {"endpoint": "http://127.0.0.1:9675", "api_key": "not-returned", "allowed_targets": ["default"]}
        self.routes.write_text(json.dumps(routes))
        self.routes.chmod(0o600)
        loaded = tools._load_routes()["profiles"]
        self.assertEqual(loaded["agentsai"]["allowed_targets"], ["default"])
        self.assertTrue(loaded["agentsai"]["endpoint"].startswith("http://127.0.0.1:"))


class MissingApprovalIncidentTests(TeamApprovalQueueTests):
    def _seed_missing_run(self):
        return tools._store_coordination_run({
            "trace_id": "a2a-default-delivery-missing",
            "calling_profile": "default",
            "target_profile": "delivery",
            "run_id": "run_missing",
            "parent_session_id": "session_jarvis",
            "objective": "Bounded specialist work",
            "created_at": 100.0,
        })

    @staticmethod
    def _missing_status():
        return {"run_id": "run_missing", "status": "waiting_for_approval", "pending_approvals": []}

    @staticmethod
    def _valid_status():
        return {"run_id": "run_missing", "status": "waiting_for_approval", "pending_approvals": [{
            "request_id": "apr_recovered", "run_id": "run_missing",
            "command_preview": "python -m unittest safe_test",
            "description": "bounded internal test", "pattern_keys": ["terminal"],
        }]}

    def test_missing_approval_is_debounced_then_incident_is_deduplicated(self):
        self._seed_missing_run()
        notices = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            if url.endswith("/v1/runs/run_missing"):
                return self._missing_status()
            if url.endswith("/v1/runs"):
                notices.append((body, idempotency_key))
                return {"run_id": "jarvis_incident", "status": "started"}
            self.fail(f"forbidden request: {method} {url}")
        with patch.object(tools, "_request", side_effect=fake_request):
            first = tools._reconcile_once(now=101.0)
            too_soon = tools._reconcile_once(now=102.0)
            second = tools._reconcile_once(now=106.0)
            third = tools._reconcile_once(now=111.0)
        self.assertEqual(first["missing_approval_incidents_delivered"], 0)
        self.assertEqual(too_soon["missing_approval_incidents_delivered"], 0)
        self.assertEqual(second["missing_approval_incidents_delivered"], 1)
        self.assertEqual(third["missing_approval_incidents_delivered"], 0)
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0][1], "missing-approval-incident-a2a-default-delivery-missing-run_missing-delivery")

    def test_observation_and_dedupe_persist_across_reconciler_restart(self):
        self._seed_missing_run()
        with patch.object(tools, "_request", return_value=self._missing_status()):
            tools._reconcile_once(now=101.0)
        # Simulate a fresh reconciler process by relying only on the SQLite row.
        notices = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            if url.endswith("/v1/runs/run_missing"):
                return self._missing_status()
            notices.append(idempotency_key)
            return {"run_id": "jarvis_incident", "status": "started"}
        with patch.object(tools, "_request", side_effect=fake_request):
            tools._reconcile_once(now=106.0)
            tools._reconcile_once(now=111.0)
        self.assertEqual(len(notices), 1)
        with tools._db_connect() as conn:
            row = conn.execute("SELECT * FROM missing_approval_episode").fetchone()
        self.assertEqual(row["observation_count"], 3)
        self.assertEqual(row["incident_delivery_state"], "delivered")

    def test_late_valid_correlated_approval_queues_normally_and_sends_one_recovery(self):
        self._seed_missing_run()
        statuses = [self._missing_status(), self._missing_status(), self._valid_status(), self._valid_status()]
        notices = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            if url.endswith("/v1/runs/run_missing"):
                return statuses.pop(0)
            if url.endswith("/v1/runs"):
                notices.append((body["input"], idempotency_key))
                return {"run_id": "jarvis_notice", "status": "started"}
            self.fail(f"forbidden request: {method} {url}")
        with patch.object(tools, "_request", side_effect=fake_request), \
             patch.object(tools, "_auto_resolve_if_covered", return_value={"ok": False, "covered": True, "lane": "auto"}) as auto:
            tools._reconcile_once(now=101.0)
            tools._reconcile_once(now=106.0)
            recovered = tools._reconcile_once(now=111.0)
            repeated = tools._reconcile_once(now=116.0)
        self.assertEqual(recovered["missing_approval_recoveries_delivered"], 1)
        self.assertEqual(repeated["missing_approval_recoveries_delivered"], 0)
        self.assertEqual(sum("MISSING APPROVAL RECOVERED" in prompt for prompt, _ in notices), 1)
        self.assertEqual(sum("MISSING APPROVAL INCIDENT" in prompt for prompt, _ in notices), 1)
        auto.assert_not_called()  # Alert-only recovery never makes an approval decision.
        with tools._db_connect() as conn:
            approval = conn.execute("SELECT request_id FROM approval_request WHERE request_id='apr_recovered'").fetchone()
            episode = conn.execute("SELECT * FROM missing_approval_episode").fetchone()
        self.assertIsNotNone(approval)
        self.assertEqual(episode["recovery_delivery_state"], "delivered")

    def test_apr_identifier_without_authoritative_object_shape_is_invalid(self):
        self.assertIsNone(tools._valid_pending_approval_event({
            "run_id": "run_missing", "status": "waiting_for_approval",
            "pending_approvals": [{"request_id": "apr_looks_valid", "run_id": "run_missing"}],
        }, "run_missing"))

    def test_mismatched_or_shape_only_apr_never_recovers_or_approves(self):
        self._seed_missing_run()
        malformed = {"run_id": "run_missing", "status": "waiting_for_approval", "pending_approvals": [{
            "request_id": "apr_looks_valid", "run_id": "different_run",
            "command_preview": "token=super-secret-value", "description": "password=hunter2",
        }]}
        notices = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            if url.endswith("/v1/runs/run_missing"):
                return malformed
            if "/approval" in url:
                self.fail("missing-approval handling must never approve")
            if url.endswith("/v1/runs"):
                notices.append((body["input"], idempotency_key))
                return {"run_id": "jarvis_incident", "status": "started"}
            self.fail(f"unexpected request: {method} {url}")
        with patch.object(tools, "_request", side_effect=fake_request), \
             patch.object(tools, "_auto_resolve_if_covered") as auto:
            tools._reconcile_once(now=101.0)
            tools._reconcile_once(now=106.0)
        auto.assert_not_called()
        self.assertEqual(len(notices), 1)
        self.assertNotIn("super-secret-value", notices[0][0])
        self.assertNotIn("hunter2", notices[0][0])
        with tools._db_connect() as conn:
            serialized = " ".join(str(value) for row in conn.execute(
                "SELECT trace_id,run_id,target_profile,status FROM missing_approval_episode"
            ) for value in row)
        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("hunter2", serialized)

    def test_alert_only_path_has_no_restart_retry_or_specialist_run_side_effect(self):
        self._seed_missing_run()
        calls = []
        def fake_request(url, key, method, body=None, idempotency_key=None):
            calls.append((url, method, body, idempotency_key))
            if url.endswith("/v1/runs/run_missing"):
                return self._missing_status()
            if url == "http://127.0.0.1:9661/v1/runs":
                return {"run_id": "jarvis_incident", "status": "started"}
            self.fail(f"forbidden retry or specialist side effect: {method} {url}")
        with patch.object(tools, "_request", side_effect=fake_request), \
             patch.object(tools, "respond_team_approval") as approve:
            tools._reconcile_once(now=101.0)
            tools._reconcile_once(now=106.0)
            tools._reconcile_once(now=111.0)
        approve.assert_not_called()
        self.assertFalse(any("/approval" in url for url, *_ in calls))
        self.assertFalse(any(url == "http://127.0.0.1:9999/v1/runs" for url, *_ in calls))

    def test_missing_approval_schema_migration_is_idempotent(self):
        tools._init_approval_db()
        tools._init_approval_db()
        with tools._db_connect() as conn:
            tables = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='missing_approval_episode'"
            ).fetchone()[0]
            indexes = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='missing_approval_episode_delivery_idx'"
            ).fetchone()[0]
        self.assertEqual(tables, 1)
        self.assertEqual(indexes, 1)


if __name__ == "__main__":
    unittest.main()
