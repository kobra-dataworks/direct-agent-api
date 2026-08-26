import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


TOOLS_PATH = Path(__file__).resolve().parents[1] / "tools.py"
SPEC = importlib.util.spec_from_file_location("direct_agent_api_development_tools_under_test", TOOLS_PATH)
tools = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = tools
SPEC.loader.exec_module(tools)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def development_context(*, phase="developer", run_host="136.243.58.118", expired=False):
    now = datetime.now(timezone.utc)
    expiry = now - timedelta(minutes=1) if expired else now + timedelta(hours=1)
    customer = {"entity_id": "kobradataworks", "canonical_name": "KoBra Dataworks GmbH", "aliases": ["KoBra"]}
    project = {
        "project_id": "development-control-plane",
        "name": "KoBra AI-Agent-Team / Development Control Plane",
        "aliases": ["AI-Agent-Team"],
        "repository": "/home/jan/.hermes/plugins/direct-agent-api",
    }
    task = {
        "objective": "Verify governed development admission without changing product code",
        "non_goals": ["No deployment", "No customer application changes"],
        "baseline_commit": None,
        "candidate_artifact_digest": None,
        "target_environment": "local control plane",
        "acceptance_criteria": ["Admission is fail closed"],
        "timeout_seconds": 300,
        "resource_class": "light",
        "deployment_authority": False,
        "placement_exception_id": None,
    }
    world = {
        "entity_id": customer["entity_id"],
        "canonical_name": customer["canonical_name"],
        "project_id": project["project_id"],
        "project_name": project["name"],
        "project_aliases": project["aliases"],
        "retrieved_at": now.isoformat(),
        "status_checked_at": now.isoformat(),
        "queries": ["development control plane placement and context"],
        "connectors": [{"name": "github", "status": "enabled", "last_successful_sync": now.isoformat()}],
        "facts": [{
            "fact": "136.243.58.118 is the approved development host",
            "source": "DEVELOPMENT_EXECUTION_PLACEMENT_POLICY.md",
            "source_date": now.isoformat(),
            "source_ref": "/home/jan/ai-agent-team/DEVELOPMENT_EXECUTION_PLACEMENT_POLICY.md",
            "relevance_reason": "Placement admission",
            "sensitivity": "internal",
            "confidence": "high",
        }],
        "warnings": [],
        "exclusions": ["credentials", "unrelated customer records"],
        "snapshot_sha256": "",
        "expires_at": expiry.isoformat(),
    }
    world["snapshot_sha256"] = canonical_hash({k: v for k, v in world.items() if k != "snapshot_sha256"})
    artifacts = {
        "project_context_sha256": canonical_hash({"customer": customer, "project": project}),
        "task_brief_sha256": canonical_hash(task),
        "permission_envelope_sha256": "a" * 64,
        "workflow_data_manifest_sha256": "b" * 64,
        "architecture_sha256": "c" * 64,
        "acceptance_sha256": canonical_hash(task["acceptance_criteria"]),
    }
    capsule = {
        "schema_version": "1.0",
        "trace_id": "capsule-test-trace",
        "customer": customer,
        "project": project,
        "developer_profile": "developer136",
        "qa_profile": "qa136",
        "workdir": "/home/jan/ai-agent-team/workspaces/development-control-plane",
        "task": task,
        "world_system": world,
        "context_artifacts": artifacts,
        "policy_versions": {
            "development_execution_placement_policy_sha256": "d" * 64,
            "development_profile_context_standard_sha256": "e" * 64,
            "development_context_capsule_schema_sha256": "f" * 64,
        },
        "created_at": now.isoformat(),
        "expires_at": expiry.isoformat(),
    }
    return {
        "work_class": "development",
        "phase": phase,
        "requested_run_host": run_host,
        "network_route": "governed-ssh-tunnel",
        "material_context_required": True,
        "required_connectors": ["github"],
        "capsule": capsule,
        "capsule_sha256": canonical_hash(capsule),
        "world_system_sha256": world["snapshot_sha256"],
    }


class DevelopmentAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.routes = root / "routes.json"
        self.db = root / "approvals.db"
        self.exceptions = root / "exceptions.json"
        self.schema = Path("/home/jan/ai-agent-team/templates/development-context-capsule.schema.json")
        self.routes.write_text(json.dumps({"profiles": {
            "default": {"endpoint": "http://127.0.0.1:9661", "api_key": "jarvis-secret", "allowed_targets": ["delivery", "developer136", "qa136"]},
            "delivery": {"endpoint": "http://127.0.0.1:9998", "api_key": "delivery-secret"},
            "developer136": {"endpoint": "http://127.0.0.1:9999", "api_key": "developer-secret", "run_host": "136.243.58.118", "network_route": "governed-ssh-tunnel", "role": "developer", "candidate_access": "isolated-worktree-write"},
            "qa136": {"endpoint": "http://127.0.0.1:9997", "api_key": "qa-secret", "run_host": "136.243.58.118", "network_route": "governed-ssh-tunnel", "role": "qa", "candidate_access": "read-only"},
        }}))
        self.routes.chmod(0o600)
        self.exceptions.write_text(json.dumps({"schema_version": "1.0", "default_development_host": "136.243.58.118", "fallback_allowed": False, "exceptions": []}))
        patches = [
            patch.object(tools, "ROUTES_PATH", self.routes),
            patch.object(tools, "APPROVAL_DB_PATH", self.db),
            patch.object(tools, "DEVELOPMENT_EXCEPTIONS_PATH", self.exceptions, create=True),
            patch.object(tools, "DEVELOPMENT_CAPSULE_SCHEMA_PATH", self.schema, create=True),
            patch.object(tools, "DEVELOPMENT_POLICY_HASHES", {"development_execution_placement_policy_sha256": "d" * 64, "development_profile_context_standard_sha256": "e" * 64, "development_context_capsule_schema_sha256": "f" * 64}, create=True),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    @staticmethod
    def completed_request(calls):
        def fake(url, key, method, body=None, idempotency_key=None):
            calls.append((url, key, method, body))
            if method == "POST":
                return {"run_id": f"run-{len(calls)}", "status": "completed"}
            return {"run_id": "run", "status": "completed", "output": "PASS"}
        return fake

    def call(self, context, calls, *, target="developer136", objective=None):
        objective = objective or context["capsule"]["task"]["objective"]
        with patch.object(tools, "_profile_name", return_value="default"), patch.object(tools, "_request", side_effect=self.completed_request(calls)):
            return json.loads(tools.coordinate_agent({
                "target": target,
                "objective": objective,
                "development_context": context,
                "wait_seconds": 1,
            }))

    def test_valid_development_capsule_routes_only_to_developer136(self):
        calls = []
        result = self.call(development_context(), calls, target="")
        self.assertTrue(result["ok"])
        self.assertEqual(result["target"], "developer136")
        self.assertIn("127.0.0.1:9999", calls[0][0])
        prompt = calls[0][3]["input"]
        self.assertIn("136.243.58.118", prompt)
        self.assertIn("capsule_sha256", prompt)

    def test_gx10_or_non136_host_is_rejected_before_network(self):
        calls = []
        result = self.call(development_context(run_host="GX10"), calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_placement_denied")
        self.assertEqual(calls, [])

    def test_incomplete_or_expired_exception_is_rejected(self):
        self.exceptions.write_text(json.dumps({"schema_version": "1.0", "default_development_host": "136.243.58.118", "fallback_allowed": False, "exceptions": [{
            "exception_id": "apiando-live-vpn-category", "project": "Apiando", "status": "pending_exact_host_verification", "approved_run_host": None,
            "allowed_repositories": [], "allowed_targets": [], "valid_from": None, "expires_at": None,
        }]}))
        ctx = development_context(run_host="apiando-vpn-host")
        ctx["capsule"]["project"]["name"] = "Apiando"
        ctx["capsule"]["world_system"]["project_name"] = "Apiando"
        ctx["capsule"]["task"]["placement_exception_id"] = "apiando-live-vpn-category"
        world = ctx["capsule"]["world_system"]
        world["snapshot_sha256"] = canonical_hash({k: v for k, v in world.items() if k != "snapshot_sha256"})
        ctx["world_system_sha256"] = world["snapshot_sha256"]
        ctx["capsule"]["context_artifacts"]["project_context_sha256"] = canonical_hash({"customer": ctx["capsule"]["customer"], "project": ctx["capsule"]["project"]})
        ctx["capsule"]["context_artifacts"]["task_brief_sha256"] = canonical_hash(ctx["capsule"]["task"])
        ctx["capsule_sha256"] = canonical_hash(ctx["capsule"])
        calls = []
        result = self.call(ctx, calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_placement_denied")
        self.assertEqual(calls, [])

    def test_missing_or_stale_world_context_is_rejected(self):
        for mutation in ("missing", "stale"):
            with self.subTest(mutation=mutation):
                ctx = development_context(expired=mutation == "stale")
                if mutation == "missing":
                    del ctx["capsule"]["world_system"]
                ctx["capsule_sha256"] = canonical_hash(ctx["capsule"])
                calls = []
                result = self.call(ctx, calls)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error_code"], "development_context_denied")
                self.assertEqual(calls, [])

    @staticmethod
    def candidate_manifest(artifact_digest):
        manifest = {
            "schema_version": "1.0",
            "artifact_sha256": artifact_digest,
            "source_manifest_sha256": "f" * 64,
        }
        manifest["manifest_sha256"] = canonical_hash(manifest)
        return manifest

    def developer_candidate(self, artifact_digest="1" * 64):
        ctx = development_context()
        ctx["capsule"]["task"]["candidate_manifest"] = self.candidate_manifest(artifact_digest)
        ctx["capsule"]["context_artifacts"]["task_brief_sha256"] = canonical_hash(ctx["capsule"]["task"])
        ctx["capsule_sha256"] = canonical_hash(ctx["capsule"])
        calls = []
        result = self.call(ctx, calls)
        self.assertTrue(result["ok"])
        return ctx, result

    def qa_candidate(self, ctx, developer_trace_id, artifact_digest, manifest=None, **extra):
        qa_ctx = copy.deepcopy(ctx)
        if manifest is not None:
            qa_ctx["capsule"]["task"]["candidate_manifest"] = manifest
            qa_ctx["capsule"]["context_artifacts"]["task_brief_sha256"] = canonical_hash(qa_ctx["capsule"]["task"])
            qa_ctx["capsule_sha256"] = canonical_hash(qa_ctx["capsule"])
        qa_ctx.update({
            "phase": "qa",
            "developer_trace_id": developer_trace_id,
            "candidate_artifact_digest": artifact_digest,
        })
        qa_ctx.update(extra)
        calls = []
        return self.call(qa_ctx, calls, target="qa136"), calls

    def test_qa_rejects_arbitrary_valid_digest_not_bound_to_developer_candidate(self):
        ctx, developer = self.developer_candidate("1" * 64)
        qa, calls = self.qa_candidate(
            ctx, developer["trace_id"], "2" * 64, candidate_read_only=True
        )
        self.assertFalse(qa["ok"])
        self.assertEqual(qa["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_qa_rejects_digest_different_from_developer_record(self):
        ctx, developer = self.developer_candidate("1" * 64)
        qa, calls = self.qa_candidate(
            ctx, developer["trace_id"], "2" * 64, candidate_read_only=True
        )
        self.assertFalse(qa["ok"])
        self.assertEqual(qa["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_qa_rejects_developer_record_without_candidate(self):
        ctx = development_context()
        developer_calls = []
        developer = self.call(ctx, developer_calls)
        self.assertTrue(developer["ok"])
        qa, calls = self.qa_candidate(
            ctx, developer["trace_id"], "1" * 64, candidate_read_only=True
        )
        self.assertFalse(qa["ok"])
        self.assertEqual(qa["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_qa_rejects_forged_candidate_read_only_boolean(self):
        ctx, developer = self.developer_candidate("1" * 64)
        qa, calls = self.qa_candidate(
            ctx, developer["trace_id"], "1" * 64, candidate_read_only=True
        )
        self.assertFalse(qa["ok"])
        self.assertEqual(qa["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_qa_rejects_candidate_manifest_artifact_mismatch(self):
        ctx, developer = self.developer_candidate("1" * 64)
        qa, calls = self.qa_candidate(
            ctx, developer["trace_id"], "1" * 64, self.candidate_manifest("2" * 64)
        )
        self.assertFalse(qa["ok"])
        self.assertEqual(qa["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_qa_accepts_exact_developer_candidate_record_and_manifest(self):
        ctx, developer = self.developer_candidate("1" * 64)
        qa, calls = self.qa_candidate(ctx, developer["trace_id"], "1" * 64)
        self.assertTrue(qa["ok"])
        self.assertEqual(qa["candidate_artifact_digest"], "1" * 64)
        self.assertIn("read-only", calls[0][3]["input"])

    def test_terminal_developer_manifest_is_bound_to_existing_admission(self):
        ctx = development_context()
        manifest = self.candidate_manifest("1" * 64)
        output = json.dumps({"implementation_evidence": {"candidate_manifest": manifest}})
        calls = []

        def completed_with_manifest(url, key, method, body=None, idempotency_key=None):
            calls.append((url, key, method, body))
            if method == "POST":
                return {"run_id": "run-terminal-manifest", "status": "running"}
            return {"run_id": "run-terminal-manifest", "status": "completed", "output": output}

        with patch.object(tools, "_profile_name", return_value="default"), patch.object(
            tools, "_request", side_effect=completed_with_manifest
        ):
            result = json.loads(tools.coordinate_agent({
                "target": "developer136",
                "objective": ctx["capsule"]["task"]["objective"],
                "development_context": ctx,
                "wait_seconds": 1,
            }))

        self.assertTrue(result["ok"])
        self.assertEqual(result["candidate_artifact_digest"], "1" * 64)
        with tools._db_connect() as conn:
            row = conn.execute(
                "SELECT candidate_artifact_digest,candidate_manifest_sha256,candidate_manifest_json "
                "FROM development_admission WHERE trace_id=?",
                (result["trace_id"],),
            ).fetchone()
        self.assertEqual(row["candidate_artifact_digest"], "1" * 64)
        self.assertEqual(row["candidate_manifest_sha256"], manifest["manifest_sha256"])
        self.assertEqual(json.loads(row["candidate_manifest_json"]), manifest)

    def test_qa_uses_terminal_manifest_from_same_capsule_without_mutating_task(self):
        ctx = development_context()
        manifest = self.candidate_manifest("1" * 64)
        output = json.dumps({"implementation_evidence": {"candidate_manifest": manifest}})
        calls = []

        def completed_with_manifest(url, key, method, body=None, idempotency_key=None):
            calls.append((url, key, method, body))
            if method == "POST":
                return {"run_id": "run-terminal-qa", "status": "running"}
            return {"run_id": "run-terminal-qa", "status": "completed", "output": output}

        with patch.object(tools, "_profile_name", return_value="default"), patch.object(
            tools, "_request", side_effect=completed_with_manifest
        ):
            developer = json.loads(tools.coordinate_agent({
                "target": "developer136",
                "objective": ctx["capsule"]["task"]["objective"],
                "development_context": ctx,
                "wait_seconds": 1,
            }))
        qa, qa_calls = self.qa_candidate(ctx, developer["trace_id"], "1" * 64)
        self.assertTrue(qa["ok"])
        self.assertEqual(qa["candidate_artifact_digest"], "1" * 64)
        self.assertIn("read-only", qa_calls[0][3]["input"])

    def test_free_text_context_is_rejected_for_development_profiles(self):
        calls = []
        ctx = development_context()
        with patch.object(tools, "_profile_name", return_value="default"), patch.object(tools, "_request", side_effect=self.completed_request(calls)):
            result = json.loads(tools.coordinate_agent({
                "target": "developer136", "objective": ctx["capsule"]["task"]["objective"],
                "context": "unbound mutable context", "development_context": ctx, "wait_seconds": 1,
            }))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_non_development_specialist_route_is_unchanged(self):
        calls = []
        with patch.object(tools, "_profile_name", return_value="default"), patch.object(tools, "_request", side_effect=self.completed_request(calls)):
            result = json.loads(tools.coordinate_agent({"target": "delivery", "objective": "Read-only specialist check", "context": "bounded", "wait_seconds": 1}))
        self.assertTrue(result["ok"])
        self.assertEqual(result["target"], "delivery")
        self.assertIn("127.0.0.1:9998", calls[0][0])

    def test_development_alias_targets_cannot_bypass_structured_admission(self):
        routes = json.loads(self.routes.read_text())
        routes["profiles"]["default"]["allowed_targets"].extend(["platform136", "apiando136"])
        routes["profiles"]["platform136"] = {"endpoint": "http://127.0.0.1:9996", "api_key": "platform-secret"}
        routes["profiles"]["apiando136"] = {"endpoint": "http://127.0.0.1:9995", "api_key": "apiando-secret"}
        self.routes.write_text(json.dumps(routes))
        self.routes.chmod(0o600)
        for target in ("platform136", "apiando136"):
            with self.subTest(target=target):
                calls = []
                with patch.object(tools, "_profile_name", return_value="default"), patch.object(tools, "_request", side_effect=self.completed_request(calls)):
                    result = json.loads(tools.coordinate_agent({"target": target, "objective": "development work", "wait_seconds": 1}))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error_code"], "development_context_denied")
                self.assertEqual(calls, [])

    def test_route_binding_mismatch_is_rejected_before_network(self):
        routes = json.loads(self.routes.read_text())
        routes["profiles"]["developer136"]["run_host"] = "GX10"
        self.routes.write_text(json.dumps(routes))
        self.routes.chmod(0o600)
        calls = []
        result = self.call(development_context(), calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_route_denied")
        self.assertEqual(calls, [])

    def test_non_owner_only_route_file_is_rejected_before_network(self):
        self.routes.chmod(0o644)
        calls = []
        result = self.call(development_context(), calls)
        self.assertFalse(result["ok"])
        self.assertEqual(calls, [])

    def test_stale_required_connector_cannot_use_caller_opt_out(self):
        ctx = development_context()
        ctx["material_context_required"] = False
        ctx["capsule"]["world_system"]["connectors"][0]["status"] = "failed"
        world = ctx["capsule"]["world_system"]
        world["snapshot_sha256"] = canonical_hash({k: v for k, v in world.items() if k != "snapshot_sha256"})
        ctx["world_system_sha256"] = world["snapshot_sha256"]
        ctx["capsule_sha256"] = canonical_hash(ctx["capsule"])
        calls = []
        result = self.call(ctx, calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_secret_shaped_capsule_value_is_rejected_before_network(self):
        ctx = development_context()
        ctx["capsule"]["world_system"]["facts"][0]["fact"] = "api_key=super-secret-value"
        world = ctx["capsule"]["world_system"]
        world["snapshot_sha256"] = canonical_hash({k: v for k, v in world.items() if k != "snapshot_sha256"})
        ctx["world_system_sha256"] = world["snapshot_sha256"]
        ctx["capsule_sha256"] = canonical_hash(ctx["capsule"])
        calls = []
        result = self.call(ctx, calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_context_denied")
        self.assertEqual(calls, [])

    def test_cross_project_world_snapshot_is_rejected_before_network(self):
        ctx = development_context()
        ctx["capsule"]["world_system"]["project_id"] = "another-customer-project"
        world = ctx["capsule"]["world_system"]
        world["snapshot_sha256"] = canonical_hash({k: v for k, v in world.items() if k != "snapshot_sha256"})
        ctx["world_system_sha256"] = world["snapshot_sha256"]
        ctx["capsule_sha256"] = canonical_hash(ctx["capsule"])
        calls = []
        result = self.call(ctx, calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "development_context_denied")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
