import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


TOOLS_PATH = Path(__file__).resolve().parents[1] / "tools.py"
SPEC = importlib.util.spec_from_file_location("direct_agent_api_hmac_tools_under_test", TOOLS_PATH)
tools = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = tools
SPEC.loader.exec_module(tools)


class HmacAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.routes = Path(self.tmp.name) / "routes.json"
        self.routes.write_text(json.dumps({"profiles": {
            "default": {"allowed_targets": ["developer136"]},
            "developer136": {
                "endpoint": "http://127.0.0.1:9999",
                "api_key": "legacy-bearer-for-dual-mode",
                "auth": {
                    "protocol_version": "direct-agent-hmac-v1",
                    "mode": "dual",
                    "direction": "default->developer136",
                    "current": {"key_id": "default-to-dev-current", "secret_env": "DA_HMAC_CURRENT"},
                    "next": {"key_id": "default-to-dev-next", "secret_env": "DA_HMAC_NEXT"},
                },
            },
        }}))
        self.routes.chmod(0o600)
        os.environ["DA_HMAC_CURRENT"] = "current-signing-secret"
        os.environ["DA_HMAC_NEXT"] = "next-rotation-secret"
        self.addCleanup(os.environ.pop, "DA_HMAC_CURRENT", None)
        self.addCleanup(os.environ.pop, "DA_HMAC_NEXT", None)

    def test_canonical_hmac_signature_uses_method_path_timestamp_nonce_and_body_digest(self):
        body = b'{"input":"hello"}'
        signed = tools._build_direct_agent_auth_headers(
            method="post",
            url="http://127.0.0.1:9999/v1/runs?b=2&a=1",
            body=body,
            route_cfg=json.loads(self.routes.read_text())["profiles"]["developer136"],
            caller="default",
            target="developer136",
            now=1234567890,
            nonce="nonce-123",
        )
        expected_digest = hashlib.sha256(body).hexdigest()
        canonical = "\n".join([
            "POST",
            "/v1/runs?b=2&a=1",
            "1234567890",
            "nonce-123",
            expected_digest,
            "default->developer136",
            "direct-agent-hmac-v1",
        ])
        expected_sig = hmac.new(b"current-signing-secret", canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(signed["X-Direct-Agent-Protocol"], "direct-agent-hmac-v1")
        self.assertEqual(signed["X-Direct-Agent-Key-Id"], "default-to-dev-current")
        self.assertEqual(signed["X-Direct-Agent-Body-SHA256"], expected_digest)
        self.assertEqual(signed["X-Direct-Agent-Direction"], "default->developer136")
        self.assertEqual(signed["X-Direct-Agent-Signature"], expected_sig)

    def test_verifier_accepts_current_or_next_once_and_rejects_replay(self):
        cache = tools.HmacNonceCache(max_entries=10)
        body = b'{"input":"hello"}'
        headers = tools._build_direct_agent_auth_headers(
            method="POST",
            url="http://127.0.0.1:9999/v1/runs",
            body=body,
            route_cfg=json.loads(self.routes.read_text())["profiles"]["developer136"],
            caller="default",
            target="developer136",
            now=1_700_000_000,
            nonce="unique-nonce",
        )
        result = tools.verify_hmac_request(
            "POST", "/v1/runs", headers, body,
            secrets_by_key={"default-to-dev-current": "current-signing-secret", "default-to-dev-next": "next-rotation-secret"},
            expected_direction="default->developer136",
            nonce_cache=cache,
            now=1_700_000_010,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["protocol_version"], "direct-agent-hmac-v1")
        self.assertEqual(result["key_id"], "default-to-dev-current")
        next_headers = dict(headers)
        next_headers["X-Direct-Agent-Key-Id"] = "default-to-dev-next"
        next_headers["X-Direct-Agent-Nonce"] = "unique-next-nonce"
        canonical = "\n".join([
            "POST", "/v1/runs", "1700000000", "unique-next-nonce",
            next_headers["X-Direct-Agent-Body-SHA256"], "default->developer136", "direct-agent-hmac-v1",
        ])
        next_headers["X-Direct-Agent-Signature"] = hmac.new(
            b"next-rotation-secret", canonical.encode(), hashlib.sha256
        ).hexdigest()
        next_result = tools.verify_hmac_request(
            "POST", "/v1/runs", next_headers, body,
            secrets_by_key={"default-to-dev-current": "current-signing-secret", "default-to-dev-next": "next-rotation-secret"},
            expected_direction="default->developer136",
            nonce_cache=cache,
            now=1_700_000_010,
        )
        self.assertTrue(next_result["ok"])
        self.assertEqual(next_result["key_id"], "default-to-dev-next")
        replay = tools.verify_hmac_request(
            "POST", "/v1/runs", headers, body,
            secrets_by_key={"default-to-dev-current": "current-signing-secret"},
            expected_direction="default->developer136",
            nonce_cache=cache,
            now=1_700_000_011,
        )
        self.assertFalse(replay["ok"])
        self.assertEqual(replay["error_code"], "replayed_nonce")

    def test_verifier_rejects_malformed_expired_future_tampered_and_wrong_route(self):
        body = b'{"input":"hello"}'
        base = tools._build_direct_agent_auth_headers(
            method="POST",
            url="http://127.0.0.1:9999/v1/runs",
            body=body,
            route_cfg=json.loads(self.routes.read_text())["profiles"]["developer136"],
            caller="default",
            target="developer136",
            now=1_700_000_000,
            nonce="nonce-base",
        )
        cases = {
            "malformed_auth": ({k: v for k, v in base.items() if k != "X-Direct-Agent-Signature"}, body, 1_700_000_000, "malformed_auth"),
            "expired_timestamp": (base | {"X-Direct-Agent-Nonce": "nonce-expired"}, body, 1_700_000_061, "expired_timestamp"),
            "future_timestamp": (base | {"X-Direct-Agent-Nonce": "nonce-future"}, body, 1_699_999_939, "future_timestamp"),
            "tampered_body": (base | {"X-Direct-Agent-Nonce": "nonce-tampered"}, b'{"input":"evil"}', 1_700_000_000, "body_digest_mismatch"),
            "wrong_route": (base | {"X-Direct-Agent-Direction": "developer136->default", "X-Direct-Agent-Nonce": "nonce-route"}, body, 1_700_000_000, "wrong_route"),
        }
        for name, (headers, request_body, now, error_code) in cases.items():
            with self.subTest(name=name):
                result = tools.verify_hmac_request(
                    "POST", "/v1/runs", headers, request_body,
                    secrets_by_key={"default-to-dev-current": "current-signing-secret"},
                    expected_direction="default->developer136",
                    nonce_cache=tools.HmacNonceCache(max_entries=10),
                    now=now,
                )
                self.assertFalse(result["ok"])
                self.assertEqual(result["error_code"], error_code)
                self.assertNotIn("current-signing-secret", json.dumps(result))

    def test_request_transitional_dual_mode_sends_hmac_and_legacy_bearer_without_logging_secret_values(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False
            def read(self, limit):
                return b'{"ok": true}'

        def fake_open(req, timeout):
            captured["headers"] = dict(req.header_items())
            return Response()

        route_cfg = json.loads(self.routes.read_text())["profiles"]["developer136"]
        with patch.object(tools.urllib.request, "urlopen", side_effect=fake_open), \
             patch.object(tools, "_profile_name", return_value="default"), \
             patch.object(tools.uuid, "uuid4", return_value=type("U", (), {"hex": "0" * 32, "__str__": lambda self: "uuid"})()):
            result = tools._request(
                "http://127.0.0.1:9999/v1/runs",
                "legacy-bearer-for-dual-mode",
                "POST",
                {"input": "hello"},
                route_cfg=route_cfg,
                caller="default",
                target="developer136",
            )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(captured["headers"]["Authorization"], "Bearer legacy-bearer-for-dual-mode")
        self.assertEqual(captured["headers"]["X-direct-agent-protocol"], "direct-agent-hmac-v1")
        self.assertEqual(captured["headers"]["X-direct-agent-auth-mode"], "dual")
        self.assertNotIn("current-signing-secret", json.dumps(captured))


if __name__ == "__main__":
    unittest.main()
