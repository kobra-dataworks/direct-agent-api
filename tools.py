"""Controlled direct HTTP invocation of approved local Hermes profiles.

Secrets never enter the model-visible schema or returned tool payload. Routes are
kept in ~/.hermes/direct-agent-api-routes.json with owner-only permissions.
Cross-profile approval requests are persisted in an owner-only SQLite queue and
can only be resolved by the default (Jarvis) profile.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROUTES_PATH = Path.home() / ".hermes" / "direct-agent-api-routes.json"
APPROVAL_DB_PATH = Path.home() / ".hermes" / "team-approvals.db"
DEVELOPMENT_EXCEPTIONS_PATH = Path("/home/jan/ai-agent-team/inventory/development-placement-exceptions.json")
DEVELOPMENT_CAPSULE_SCHEMA_PATH = Path("/home/jan/ai-agent-team/templates/development-context-capsule.schema.json")
DEVELOPMENT_POLICY_PATHS = {
    "development_execution_placement_policy_sha256": Path("/home/jan/ai-agent-team/DEVELOPMENT_EXECUTION_PLACEMENT_POLICY.md"),
    "development_profile_context_standard_sha256": Path("/home/jan/ai-agent-team/DEVELOPMENT_PROFILE_CONTEXT_STANDARD.md"),
    "development_context_capsule_schema_sha256": DEVELOPMENT_CAPSULE_SCHEMA_PATH,
}
DEFAULT_DEVELOPMENT_HOST = "136.243.58.118"
DEVELOPMENT_PROFILES = {"developer136", "qa136", "platform136", "apiando136", "developer", "coding"}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|password|secret|private[_ -]?key)\s*[:=]\s*[^\s,;]{4,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
MAX_TASK_CHARS = 12_000
MAX_RESULT_CHARS = 18_000
MAX_WAIT_SECONDS = 180
APPROVAL_TTL_SECONDS = 900
RECONCILE_INTERVAL_SECONDS = 5
RETRY_INTERVAL_SECONDS = 30
MISSING_APPROVAL_CONFIRMATIONS = 2
MISSING_APPROVAL_REOBSERVE_SECONDS = RECONCILE_INTERVAL_SECONDS
MISSING_APPROVAL_RETENTION_SECONDS = 30 * 24 * 60 * 60
COMPANY_STAGING_SUFFIXES = ("kobra.cloud", "kobra-dataworks.de")
TERMINAL_STATES = {"completed", "failed", "cancelled"}
PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
REQUEST_RE = re.compile(r"^apr_[a-f0-9]{8,64}$|^apr_[A-Za-z0-9_-]{3,120}$")


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


DEVELOPMENT_POLICY_HASHES = {name: _sha256_file(path) for name, path in DEVELOPMENT_POLICY_PATHS.items()}
CURRENT_GOAL_MANDATE = {
    "mandate_id": "gm_kobra_operating_authority_20260725",
    "goal": "Make Agent Operations Intelligence functional under Jarvis-first operating authority.",
    "measurable_outcome": "Bounded work executes without repeated Jan prompts; only credible material harm pauses for one Decision Packet.",
    "scope": {
        "organisation": "KoBra Dataworks",
        "owners": ["default", "openexo"],
        "specialists": ["delivery", "developer", "coding", "qa", "onboarding", "leni", "donna", "agentsai", "marketing", "sales", "dondraper"],
        "action_classes": ["diagnosis", "implementation", "tests", "qa", "deployment", "recovery", "credentials", "external-communication", "financial-legal", "destructive"],
        "human_escalation_boundary": "credible material harm to KoBra Dataworks",
    },
    "owner": "default",
    "rollback_path": "restore the predeploy plugin artifact and reload gateway/reconciler",
    "acceptance_gate": "governance/context/runtime/activation/safe-E2E/harm-negative all PASS",
    "decision_evidence": "Jan Telegram 2026-07-25",
    "approved_at": 1785002400.0,
    "status": "active",
}

COORDINATE_AGENT_SCHEMA = {
    "name": "coordinate_agent",
    "description": (
        "Invoke an explicitly authorised Hermes specialist profile through its local API. "
        "Use this for bounded specialist work only. Do not use it for external communication, "
        "deployments, credential changes, payments, or work that needs a human-visible ClickUp task. "
        "If the specialist pauses for approval, a formal correlation-bound request is routed to "
        "Jarvis's team approval queue."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Approved target profile, for example openexo, onboarding, leni, or delivery.",
            },
            "objective": {
                "type": "string",
                "description": "Concrete bounded task for the specialist. Include desired decision or artifact.",
            },
            "context": {
                "type": "string",
                "description": "Relevant verified facts, source references and constraints. Never include secrets.",
            },
            "result_format": {
                "type": "string",
                "description": "Expected response format, e.g. decision_packet or implementation_evidence.",
            },
            "wait_seconds": {
                "type": "integer",
                "description": "How long to wait for completion before returning the run id. Maximum 180.",
            },
            "development_context": {
                "type": "object",
                "description": (
                    "Mandatory structured placement and immutable Context Capsule for developer136/qa136. "
                    "Free-text context is rejected for these profiles."
                ),
            },
        },
        "required": ["objective"],
    },
}

TEAM_APPROVALS_LIST_SCHEMA = {
    "name": "team_approvals_list",
    "description": "List formal cross-profile approval requests routed to Jarvis. Jarvis-only.",
    "parameters": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["pending", "escalated", "expired", "consumed", "denied", "delivery_failed", "all"],
                "description": "Queue status filter. Default pending.",
            },
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
    },
}

TEAM_APPROVAL_RESPOND_SCHEMA = {
    "name": "team_approval_respond",
    "description": (
        "Return a one-time, correlation-bound decision to a paused specialist run. "
        "Jarvis may allow once only within standing delegation; high-risk classes must be escalated to Jan."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "request_id": {"type": "string"},
            "decision": {
                "type": "string",
                "enum": ["allow-once", "deny", "escalate-to-Jan"],
            },
        },
        "required": ["request_id", "decision"],
    },
}


def _profile_name() -> str:
    home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")).resolve()
    profiles_dir = Path.home() / ".hermes" / "profiles"
    try:
        if home.parent == profiles_dir:
            return home.name
    except OSError:
        pass
    return "default"


def _load_routes() -> dict[str, Any]:
    try:
        metadata = ROUTES_PATH.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            return {}
        data = json.loads(ROUTES_PATH.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def check_available() -> bool:
    data = _load_routes()
    caller = _profile_name()
    return bool(data.get("profiles", {}).get(caller, {}).get("allowed_targets"))


def check_approval_router_available() -> bool:
    return _profile_name() == "default"


def _request(
    url: str,
    key: str,
    method: str,
    body: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": idempotency_key or str(uuid.uuid4()),
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        raw = response.read(1_000_000).decode("utf-8", errors="replace")
    parsed = json.loads(raw) if raw else {}
    return parsed if isinstance(parsed, dict) else {"raw": raw}


def _safe_text(value: Any, limit: int = MAX_RESULT_CHARS) -> str:
    text = str(value or "")
    return text[:limit] + ("\n[truncated]" if len(text) > limit else "")


def _redact_text(value: Any, limit: int) -> str:
    text = _safe_text(value, limit)
    try:
        from agent.redact import redact_sensitive_text

        text = redact_sensitive_text(text)
    except Exception:
        # Fail-safe fallback for plugin-only unit tests. The API layer already
        # redacts command payloads before they reach this plugin.
        text = re.sub(
            r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            text,
        )
    return text[:limit]


def _db_connect() -> sqlite3.Connection:
    APPROVAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(APPROVAL_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init_approval_db() -> None:
    with _db_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS approval_request (
                request_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                calling_profile TEXT NOT NULL,
                requesting_profile TEXT NOT NULL,
                paused_run_id TEXT NOT NULL,
                requested_action TEXT NOT NULL,
                tool TEXT NOT NULL,
                description TEXT NOT NULL,
                command_preview TEXT NOT NULL,
                command_sha256 TEXT NOT NULL,
                risk_class TEXT NOT NULL,
                requires_jan INTEGER NOT NULL CHECK (requires_jan IN (0,1)),
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                decided_at REAL,
                decision TEXT,
                decision_actor TEXT,
                consumed_at REAL,
                UNIQUE(requesting_profile, paused_run_id, request_id)
            );
            CREATE INDEX IF NOT EXISTS approval_request_status_idx
                ON approval_request(status, created_at);
            CREATE INDEX IF NOT EXISTS approval_request_trace_idx
                ON approval_request(trace_id);
            CREATE TABLE IF NOT EXISTS approval_event (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL REFERENCES approval_request(request_id),
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS approval_event_request_idx
                ON approval_event(request_id, occurred_at);
            CREATE TABLE IF NOT EXISTS coordination_run (
                run_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                calling_profile TEXT NOT NULL,
                target_profile TEXT NOT NULL,
                parent_session_id TEXT NOT NULL DEFAULT '',
                objective TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'started',
                resume_state TEXT NOT NULL DEFAULT 'active',
                final_delivery_state TEXT NOT NULL DEFAULT 'pending',
                final_output TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS coordination_run_state_idx
                ON coordination_run(status, final_delivery_state, updated_at);
            CREATE TABLE IF NOT EXISTS missing_approval_episode (
                trace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                target_profile TEXT NOT NULL,
                episode_number INTEGER NOT NULL DEFAULT 1,
                observation_count INTEGER NOT NULL DEFAULT 0,
                first_observed_at REAL NOT NULL,
                last_observed_at REAL NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('observing','incident','recovered','resolved_without_alert')),
                incident_delivery_state TEXT NOT NULL DEFAULT 'pending'
                    CHECK (incident_delivery_state IN ('pending','delivering','delivered')),
                recovery_delivery_state TEXT NOT NULL DEFAULT 'none'
                    CHECK (recovery_delivery_state IN ('none','pending','delivering','delivered')),
                correlated_request_id TEXT NOT NULL DEFAULT '',
                next_delivery_at REAL NOT NULL DEFAULT 0,
                delivery_attempts INTEGER NOT NULL DEFAULT 0,
                incident_delivered_at REAL,
                recovered_at REAL,
                recovery_delivered_at REAL,
                PRIMARY KEY (trace_id, run_id, target_profile)
            );
            CREATE INDEX IF NOT EXISTS missing_approval_episode_delivery_idx
                ON missing_approval_episode(status, incident_delivery_state, recovery_delivery_state, next_delivery_at);
            CREATE TABLE IF NOT EXISTS development_admission (
                trace_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (phase IN ('developer','qa')),
                project_id TEXT NOT NULL,
                run_host TEXT NOT NULL,
                target_profile TEXT NOT NULL,
                capsule_sha256 TEXT NOT NULL,
                world_system_sha256 TEXT NOT NULL,
                acceptance_sha256 TEXT NOT NULL,
                candidate_artifact_digest TEXT,
                candidate_manifest_sha256 TEXT,
                candidate_manifest_json TEXT,
                developer_trace_id TEXT,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS development_admission_project_idx
                ON development_admission(project_id, capsule_sha256, created_at);
            CREATE TABLE IF NOT EXISTS goal_mandate (
                mandate_id TEXT PRIMARY KEY,
                scope_fingerprint TEXT NOT NULL UNIQUE,
                goal TEXT NOT NULL,
                measurable_outcome TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                owner TEXT NOT NULL,
                rollback_path TEXT NOT NULL,
                acceptance_gate TEXT NOT NULL,
                decision_evidence TEXT NOT NULL,
                approved_at REAL NOT NULL,
                created_at REAL NOT NULL,
                review_at REAL,
                closed_at REAL,
                status TEXT NOT NULL CHECK (status IN ('active','closed','revoked'))
            );
            CREATE INDEX IF NOT EXISTS goal_mandate_status_idx
                ON goal_mandate(status, approved_at);
            """
        )
        existing = {row[1] for row in conn.execute("PRAGMA table_info(approval_request)")}
        migrations = {
            "parent_session_id": "TEXT NOT NULL DEFAULT ''",
            "notification_state": "TEXT NOT NULL DEFAULT 'pending'",
            "notification_attempts": "INTEGER NOT NULL DEFAULT 0",
            "notified_at": "REAL",
            "next_notification_at": "REAL NOT NULL DEFAULT 0",
            "resume_state": "TEXT NOT NULL DEFAULT 'waiting_for_decision'",
            "final_result_delivery_state": "TEXT NOT NULL DEFAULT 'pending'",
            "goal_mandate_id": "TEXT",
            "scope_fingerprint": "TEXT NOT NULL DEFAULT ''",
            "canonical_request_id": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in migrations.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE approval_request ADD COLUMN {column} {definition}")
        development_existing = {row[1] for row in conn.execute("PRAGMA table_info(development_admission)")}
        for column, definition in {
            "candidate_manifest_sha256": "TEXT",
            "candidate_manifest_json": "TEXT",
        }.items():
            if column not in development_existing:
                conn.execute(f"ALTER TABLE development_admission ADD COLUMN {column} {definition}")
        run_existing = {row[1] for row in conn.execute("PRAGMA table_info(coordination_run)")}
        for column, definition in {
            "goal_mandate_id": "TEXT",
            "scope_fingerprint": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if column not in run_existing:
                conn.execute(f"ALTER TABLE coordination_run ADD COLUMN {column} {definition}")
        conn.execute("CREATE INDEX IF NOT EXISTS approval_request_scope_idx ON approval_request(goal_mandate_id,scope_fingerprint,status)")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS approval_scope_current (
                goal_mandate_id TEXT NOT NULL,
                scope_fingerprint TEXT NOT NULL,
                canonical_request_id TEXT NOT NULL REFERENCES approval_request(request_id),
                created_at REAL NOT NULL,
                PRIMARY KEY (goal_mandate_id, scope_fingerprint)
            );
            CREATE TABLE IF NOT EXISTS approval_request_attachment (
                request_id TEXT PRIMARY KEY,
                canonical_request_id TEXT NOT NULL REFERENCES approval_request(request_id),
                paused_run_id TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS approval_request_attachment_canonical_idx
                ON approval_request_attachment(canonical_request_id, created_at);
            """
        )
        # Additive bootstrap preserves historical rows. For an existing active
        # duplicate set, the earliest request is the sole current route.
        conn.execute(
            """INSERT OR IGNORE INTO approval_scope_current(
                   goal_mandate_id,scope_fingerprint,canonical_request_id,created_at
               )
               SELECT goal_mandate_id,scope_fingerprint,MIN(request_id),MIN(created_at)
                 FROM approval_request
                WHERE goal_mandate_id IS NOT NULL AND goal_mandate_id!=''
                  AND scope_fingerprint!='' AND status IN ('pending','escalated')
                GROUP BY goal_mandate_id,scope_fingerprint"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS approval_request_canonical_idx ON approval_request(canonical_request_id,status,created_at)"
        )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS approval_event_final_result_uq
               ON approval_event(request_id,event_type)
               WHERE event_type='final_result_delivered_to_jarvis'"""
        )
    try:
        os.chmod(APPROVAL_DB_PATH, 0o600)
    except OSError:
        pass


def _canonical_fingerprint(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _action_scope_fingerprint(tool: str, description: str, command: str) -> str:
    normalize = lambda value: " ".join(str(value or "").lower().split())
    return _canonical_fingerprint({
        "tool": normalize(tool),
        "description": normalize(description),
        "command": normalize(command),
    })


def activate_goal_mandate(record: dict[str, Any]) -> dict[str, Any]:
    _init_approval_db()
    mandate_id = str(record["mandate_id"])
    scope_json = json.dumps(record["scope"], sort_keys=True, separators=(",", ":"))
    scope_fingerprint = _canonical_fingerprint(record["scope"])
    now = time.time()
    values = (
        mandate_id, scope_fingerprint, str(record["goal"]), str(record["measurable_outcome"]),
        scope_json, str(record["owner"]), str(record["rollback_path"]),
        str(record["acceptance_gate"]), str(record["decision_evidence"]),
        float(record.get("approved_at") or now), now, str(record.get("status") or "active"),
    )
    with _db_connect() as conn:
        existing = conn.execute("SELECT * FROM goal_mandate WHERE mandate_id=?", (mandate_id,)).fetchone()
        if existing and str(existing["scope_fingerprint"]) != scope_fingerprint:
            raise ValueError("goal mandate scope fingerprint is immutable")
        conn.execute(
            """INSERT OR IGNORE INTO goal_mandate(
                mandate_id,scope_fingerprint,goal,measurable_outcome,scope_json,owner,
                rollback_path,acceptance_gate,decision_evidence,approved_at,created_at,status
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        row = conn.execute("SELECT * FROM goal_mandate WHERE mandate_id=?", (mandate_id,)).fetchone()
    return dict(row) if row else {}


def get_active_goal_mandate(mandate_id: str | None = None) -> dict[str, Any] | None:
    _init_approval_db()
    with _db_connect() as conn:
        if mandate_id:
            row = conn.execute(
                "SELECT * FROM goal_mandate WHERE mandate_id=? AND status='active'", (mandate_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM goal_mandate WHERE status='active' ORDER BY approved_at DESC LIMIT 1"
            ).fetchone()
    return dict(row) if row else None


def _active_mandate_for(calling_profile: str, requesting_profile: str) -> dict[str, Any] | None:
    mandate = get_active_goal_mandate()
    if not mandate:
        return None
    try:
        scope = json.loads(str(mandate["scope_json"]))
    except Exception:
        return None
    permitted = set(scope.get("owners") or []) | set(scope.get("specialists") or [])
    if calling_profile not in permitted or requesting_profile not in permitted:
        return None
    return mandate


def _audit(conn: sqlite3.Connection, request_id: str, event_type: str, actor: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO approval_event(request_id,event_type,actor,occurred_at,detail) VALUES(?,?,?,?,?)",
        (request_id, event_type, actor, time.time(), _redact_text(detail, 500)),
    )


def _is_company_staging_domain(domain: str) -> bool:
    value = domain.lower().strip(".")
    return any(value == suffix or value.endswith(f".{suffix}") for suffix in COMPANY_STAGING_SUFFIXES)


def _classify_approval(tool: str, description: str, command: str) -> tuple[str, bool]:
    haystack = f"{tool} {description} {command}".lower()
    command_text = command.lower().strip()
    material_harm_markers = (
        "credible material harm", "material damage to kobra", "irreversible customer data loss",
        "without backup or rollback", "unbounded financial commitment", "confidentiality breach",
        "security compromise", "disable governance", "disable auditability", "irreversible production outage",
    )
    catastrophic_command = (
        re.search(r"\brm\s+(?:--?\S+\s+)*['\"]?/home/jan/\.hermes(?:/|['\"]|\s|$)", command_text)
        or re.search(r"\bdrop\s+database\s+(?:if\s+exists\s+)?[`\"\[]?production(?:[`\"\]]|\s|;|$)", command_text)
    )
    if catastrophic_command or any(marker in haystack for marker in material_harm_markers):
        return "material-harm", True

    if "bounded" in description.lower() and any(
        marker in command_text for marker in ("python -m unittest", "python3 -m unittest", "pytest")
    ):
        return "bounded-test", False

    active_communication = (
        "active customer communication", "send email", "smtp", "outlook",
        "telegram_send", "messages_send", "publish", "post publicly",
        "message active customer", "send customer", "customer message",
    )
    if any(marker in haystack for marker in active_communication):
        return "active-customer-communication", False

    domains = re.findall(r"(?<![a-z0-9-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![a-z0-9.-])", haystack)
    deployment = any(marker in haystack for marker in ("deploy", "release"))
    if deployment and "staging" in haystack:
        if domains and all(_is_company_staging_domain(domain) for domain in domains):
            return "company-staging-deploy", False
        return "customer-or-lookalike-domain", False

    classes = (
        ("credential", ("credential", "api key", "token", "password", "oauth", "private key", "secret")),
        ("financial-legal", ("payment", "invoice", "refund", "contract", "pricing", "legal", "avv", "dpa")),
        ("production", ("production", " prod ", "deploy", "release", "rollback", "systemctl", "cloudflare")),
        ("destructive", ("rm -", "delete", "drop ", "truncate ", "format ", "shutdown", "reboot", "destroy")),
        ("privacy-sensitive", ("personal data", "customer data", "cross-client", "mailbox", "calendar")),
    )
    for risk_class, markers in classes:
        if any(marker in haystack for marker in markers):
            return risk_class, False
    if not command.strip():
        return "internal-read", False
    return "internal-write", False


def _approval_lane(risk_class: str, requires_jan: bool) -> str:
    if requires_jan or risk_class == "material-harm":
        return "material-harm"
    if risk_class in {"internal-read", "bounded-test"}:
        return "auto"
    return "jarvis-review"


def _store_approval(record: dict[str, Any]) -> dict[str, Any]:
    _init_approval_db()
    request_id = str(record["request_id"])
    command_preview = _redact_text(record.get("command_preview"), 4000)
    risk_class = str(record.get("risk_class") or "")
    requires_jan = bool(record.get("requires_jan"))
    if not risk_class:
        risk_class, requires_jan = _classify_approval(
            str(record.get("tool") or "terminal"),
            str(record.get("description") or ""),
            command_preview,
        )
    mandate = _active_mandate_for(
        str(record["calling_profile"]), str(record["requesting_profile"])
    )
    goal_mandate_id = str(mandate["mandate_id"]) if mandate else None
    scope_fingerprint = _action_scope_fingerprint(
        str(record.get("tool") or "terminal"), str(record.get("description") or ""), command_preview
    )
    values = (
        request_id,
        str(record["trace_id"]),
        str(record["calling_profile"]),
        str(record["requesting_profile"]),
        str(record["paused_run_id"]),
        _redact_text(record.get("requested_action"), 1000),
        _redact_text(record.get("tool") or "terminal", 100),
        _redact_text(record.get("description"), 1000),
        command_preview,
        hashlib.sha256(command_preview.encode("utf-8")).hexdigest(),
        risk_class,
        1 if requires_jan else 0,
        "pending",
        str(record.get("parent_session_id") or ""),
        goal_mandate_id,
        scope_fingerprint,
        float(record["created_at"]),
        float(record["expires_at"]),
    )
    with _db_connect() as conn:
        # One writer claims the scope, while every native request remains a first-class row.
        conn.execute("BEGIN IMMEDIATE")
        before = conn.total_changes
        conn.execute(
            """INSERT OR IGNORE INTO approval_request(
                request_id,trace_id,calling_profile,requesting_profile,paused_run_id,
                requested_action,tool,description,command_preview,command_sha256,
                risk_class,requires_jan,status,parent_session_id,goal_mandate_id,scope_fingerprint,created_at,expires_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        inserted = conn.total_changes > before
        row = conn.execute("SELECT * FROM approval_request WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            raise RuntimeError("approval request persistence failed")
        if inserted:
            _audit(conn, request_id, "requested", str(record["requesting_profile"]))
        canonical_request_id = request_id
        if goal_mandate_id:
            current = conn.execute(
                """SELECT s.canonical_request_id,r.status FROM approval_scope_current s
                   LEFT JOIN approval_request r ON r.request_id=s.canonical_request_id
                  WHERE s.goal_mandate_id=? AND s.scope_fingerprint=?""",
                (goal_mandate_id, scope_fingerprint),
            ).fetchone()
            if current is not None and str(current["status"] or "") not in {
                "pending", "delivering", "escalated", "delivery_failed"
            }:
                conn.execute(
                    "DELETE FROM approval_scope_current WHERE goal_mandate_id=? AND scope_fingerprint=?",
                    (goal_mandate_id, scope_fingerprint),
                )
                current = None
            if current is None:
                conn.execute(
                    """INSERT INTO approval_scope_current(
                           goal_mandate_id,scope_fingerprint,canonical_request_id,created_at
                       ) VALUES(?,?,?,?)""",
                    (goal_mandate_id, scope_fingerprint, request_id, float(record["created_at"])),
                )
            else:
                canonical_request_id = str(current["canonical_request_id"])
        if inserted:
            notification_state = "pending" if canonical_request_id == request_id else "linked_to_canonical"
            conn.execute(
                "UPDATE approval_request SET canonical_request_id=?,notification_state=? WHERE request_id=?",
                (canonical_request_id, notification_state, request_id),
            )
            if canonical_request_id == request_id:
                _audit(conn, request_id, "routed_to_jarvis", "jarvis")
            else:
                _audit(conn, request_id, "equivalent_request_linked", "control-plane", canonical_request_id)
        conn.execute(
            "UPDATE coordination_run SET status='waiting_for_approval',resume_state='waiting_for_decision',updated_at=? WHERE run_id=?",
            (time.time(), str(record["paused_run_id"])),
        )
        row = conn.execute("SELECT * FROM approval_request WHERE request_id=?", (request_id,)).fetchone()
    return dict(row) if row else {}


def _store_coordination_run(record: dict[str, Any]) -> dict[str, Any]:
    _init_approval_db()
    now = float(record.get("created_at") or time.time())
    mandate = _active_mandate_for(str(record["calling_profile"]), str(record["target_profile"]))
    objective = _redact_text(record.get("objective"), 2000)
    values = (
        str(record["run_id"]), str(record["trace_id"]), str(record["calling_profile"]),
        str(record["target_profile"]), str(record.get("parent_session_id") or ""),
        objective, str(record.get("status") or "started"),
        str(mandate["mandate_id"]) if mandate else None,
        _canonical_fingerprint({"objective": " ".join(objective.lower().split()), "target": str(record["target_profile"])}),
        now, now,
    )
    with _db_connect() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO coordination_run(
                run_id,trace_id,calling_profile,target_profile,parent_session_id,objective,status,
                goal_mandate_id,scope_fingerprint,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        row = conn.execute("SELECT * FROM coordination_run WHERE run_id=?", (values[0],)).fetchone()
    return dict(row) if row else {}


def _jarvis_route() -> tuple[str, str]:
    cfg = _load_routes().get("profiles", {}).get("default", {})
    return str(cfg.get("endpoint") or "").rstrip("/"), str(cfg.get("api_key") or "")


def _notify_jarvis(row: dict[str, Any], now: float) -> bool:
    request_id = str(row["request_id"])
    canonical_request_id = str(row.get("canonical_request_id") or request_id)
    if canonical_request_id != request_id:
        return False
    lane = _approval_lane(str(row.get("risk_class") or ""), bool(row.get("requires_jan")))
    if row.get("goal_mandate_id") and lane == "auto":
        with _db_connect() as conn:
            conn.execute(
                "UPDATE approval_request SET notification_state='suppressed_by_mandate' WHERE request_id=?",
                (request_id,),
            )
        return False
    with _db_connect() as conn:
        claimed = conn.execute(
            """UPDATE approval_request
               SET notification_state='delivering',notification_attempts=notification_attempts+1,
                   next_notification_at=?
               WHERE request_id=? AND notification_state!='delivered' AND next_notification_at<=?""",
            (now + RETRY_INTERVAL_SECONDS, request_id, now),
        ).rowcount
    if claimed != 1:
        return False
    endpoint, key = _jarvis_route()
    if not endpoint or not key:
        with _db_connect() as conn:
            conn.execute("UPDATE approval_request SET notification_state='pending' WHERE request_id=?", (request_id,))
        return False
    instruction = (
        "Create exactly one consolidated Jan Decision Packet and keep the action blocked."
        if lane == "material-harm"
        else "Jarvis must decide allow-once or deny internally; do not prompt Jan without material-harm evidence."
    )
    prompt = (
        "TEAM APPROVAL REQUIRED\n"
        f"request_id: {request_id}\ntrace_id: {row['trace_id']}\n"
        f"specialist: {row['requesting_profile']}\npaused_run_id: {row['paused_run_id']}\n"
        f"risk_class: {row['risk_class']}\nrequires_jan: {bool(row['requires_jan'])}\n"
        f"approval_lane: {lane}\n"
        f"action: {_safe_text(row['requested_action'], 1000)}\n"
        f"command_preview: {_safe_text(row['command_preview'], 4000)}\n"
        f"{instruction} Never infer approval from this notification."
    )
    try:
        result = _request(
            f"{endpoint}/v1/runs", key, "POST",
            {"input": prompt, "session_id": f"team-approval:{request_id}"},
            idempotency_key=f"approval-notify-{request_id}",
        )
        if not result.get("run_id"):
            raise RuntimeError("Jarvis wake-up did not return a run id")
    except Exception:
        with _db_connect() as conn:
            conn.execute("UPDATE approval_request SET notification_state='pending' WHERE request_id=?", (request_id,))
            _audit(conn, request_id, "notification_failed", "control-plane")
        return False
    with _db_connect() as conn:
        conn.execute(
            "UPDATE approval_request SET notification_state='delivered',notified_at=? WHERE request_id=?",
            (now, request_id),
        )
        _audit(conn, request_id, "jarvis_actively_notified", "control-plane")
    return True


def _commit_final_result_delivery(run_id: str, now: float) -> None:
    """Commit run/approval parity and one audit event per exact native request."""
    with _db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE coordination_run SET final_delivery_state='delivered',updated_at=? WHERE run_id=?",
            (now, run_id),
        )
        request_rows = conn.execute(
            "SELECT request_id FROM approval_request WHERE paused_run_id=?", (run_id,)
        ).fetchall()
        conn.execute(
            "UPDATE approval_request SET final_result_delivery_state='delivered' WHERE paused_run_id=?",
            (run_id,),
        )
        for request in request_rows:
            conn.execute(
                """INSERT OR IGNORE INTO approval_event(request_id,event_type,actor,occurred_at,detail)
                   VALUES(?,?,?,?,?)""",
                (str(request["request_id"]), "final_result_delivered_to_jarvis", "control-plane", now, run_id),
            )


def _repair_final_result_delivery_audit(now: float) -> None:
    """Repair legacy partial commits without sending a second final result."""
    with _db_connect() as conn:
        run_ids = [str(row["run_id"]) for row in conn.execute(
            """SELECT DISTINCT c.run_id FROM coordination_run c
               JOIN approval_request a ON a.paused_run_id=c.run_id
               WHERE c.final_delivery_state='delivered'
                 AND a.final_result_delivery_state!='delivered'"""
        ).fetchall()]
    for run_id in run_ids:
        _commit_final_result_delivery(run_id, now)


def _deliver_final_result(row: dict[str, Any], status: str, output: str, now: float) -> bool:
    run_id = str(row["run_id"])
    with _db_connect() as conn:
        claimed = conn.execute(
            "UPDATE coordination_run SET final_delivery_state='delivering',final_output=?,updated_at=? WHERE run_id=? AND final_delivery_state!='delivered'",
            (_redact_text(output, MAX_RESULT_CHARS), now, run_id),
        ).rowcount
        if claimed:
            conn.execute(
                "UPDATE approval_request SET final_result_delivery_state='delivering' WHERE paused_run_id=?",
                (run_id,),
            )
        if claimed != 1:
            return False
    endpoint, key = _jarvis_route()
    if not endpoint or not key:
        with _db_connect() as conn:
            conn.execute("UPDATE coordination_run SET final_delivery_state='pending' WHERE run_id=?", (run_id,))
            conn.execute(
                "UPDATE approval_request SET final_result_delivery_state='pending' WHERE paused_run_id=?",
                (run_id,),
            )
        return False
    prompt = (
        "SPECIALIST FINAL RESULT\n"
        f"trace_id: {row['trace_id']}\ntarget: {row['target_profile']}\nrun_id: {run_id}\n"
        f"status: {status}\nresult: {_redact_text(output, MAX_RESULT_CHARS)}\n"
        "This is the durable return route to Jarvis. Synthesize it under the original governance boundary."
    )
    session_id = str(row.get("parent_session_id") or f"control-return:{row['trace_id']}")
    try:
        result = _request(
            f"{endpoint}/v1/runs", key, "POST", {"input": prompt, "session_id": session_id},
            idempotency_key=f"final-result-{run_id}",
        )
        if not result.get("run_id"):
            raise RuntimeError("Jarvis result handover did not return a run id")
    except Exception:
        with _db_connect() as conn:
            conn.execute("UPDATE coordination_run SET final_delivery_state='pending' WHERE run_id=?", (run_id,))
            conn.execute(
                "UPDATE approval_request SET final_result_delivery_state='pending' WHERE paused_run_id=?",
                (run_id,),
            )
        return False
    _commit_final_result_delivery(run_id, now)
    return True


def _deliver_return_to_caller(row: dict[str, Any], status: str, output: str, now: float) -> bool:
    """Return a terminal run's result to the delegating profile (the origin).

    When a delegating profile (e.g. openexo, marketing) coordinates a run via
    ``coordinate_agent`` it only learns the outcome while it blocks in the
    ``wait_seconds`` loop. Runs that finish *after* the window (or that were
    resumed/requeued) leave the origin unaware of completion. This delivers the
    final result asynchronously back to the originating profile so a delegating
    agent is informed when a delegated task completes -- even well after it
    stopped polling.

    The coordinator (default) can reach every profile via ``allowed_targets`` in
    direct-agent-api-routes.json, so the POST route is pre-approved. Idempotent
    per run via ``final_return_delivery_state`` so the reconciler never double
    delivers. Loops are impossible: the coordinator only delivers to profiles in
    ``default.allowed_targets``, never to itself, and the call is tracked in a
    distinct column from the Jarvis final-result delivery.
    """
    run_id = str(row["run_id"])
    calling_profile = str(row.get("calling_profile") or "").strip()
    if not calling_profile:
        return False
    routes = _load_routes()
    caller_cfg = routes.get("profiles", {}).get(calling_profile, {})
    endpoint = str(caller_cfg.get("endpoint") or "").rstrip("/")
    key = str(caller_cfg.get("api_key") or "")
    if not endpoint or not key:
        return False
    # Never loop back to the coordinator itself.
    if calling_profile == "default":
        return False
    prompt = (
        "SPECIALIST FINAL RESULT (ORIGIN RETURN)\n"
        f"trace_id: {row['trace_id']}\norigin: {calling_profile}\n"
        f"target: {row['target_profile']}\nrun_id: {run_id}\n"
        f"status: {status}\nresult: {_redact_text(output, MAX_RESULT_CHARS)}\n"
        "You delegated this run to a specialist and it has now completed. "
        "Report the finished result back to your own user in your own profile's "
        "tone and channel. Synthesize it under the original governance boundary; "
        "do not re-coordinate, re-delegate, or create further coordination runs."
    )
    session_id = str(row.get("parent_session_id") or f"origin-return:{row['trace_id']}")
    try:
        resp = _request(
            f"{endpoint}/v1/runs", key, "POST",
            {"input": prompt, "session_id": session_id},
            idempotency_key=f"origin-return-{run_id}",
        )
        if not resp.get("run_id"):
            raise RuntimeError("Origin did not return a run id")
    except Exception:
        return False
    return True


def _valid_pending_approval_event(
    latest: dict[str, Any], expected_run_id: str
) -> dict[str, Any] | None:
    """Return only an authoritative, structurally valid, run-bound approval."""
    if str(latest.get("run_id") or "") != expected_run_id:
        return None
    pending = latest.get("pending_approvals")
    if not isinstance(pending, list):
        return None
    for event in pending:
        if not isinstance(event, dict):
            continue
        request_id = str(event.get("request_id") or "")
        event_run_id = str(event.get("run_id") or "")
        pattern_keys = event.get("pattern_keys", [])
        command_preview = event.get("command_preview", event.get("command"))
        event_name = str(event.get("event") or "approval.request")
        choices = event.get("choices")
        if (
            REQUEST_RE.fullmatch(request_id)
            and event_run_id == expected_run_id
            and isinstance(pattern_keys, list)
            and all(isinstance(item, str) for item in pattern_keys)
            and isinstance(command_preview, str)
            and isinstance(event.get("description", ""), str)
            and event_name == "approval.request"
            and (choices is None or (
                isinstance(choices, list)
                and "deny" in choices
                and any(choice in choices for choice in ("once", "session", "always"))
            ))
        ):
            return event
    return None


def _observe_missing_approval(run: dict[str, Any], now: float) -> dict[str, Any]:
    """Persist a debounced anomaly episode without storing remote payload data."""
    key = (str(run["trace_id"]), str(run["run_id"]), str(run["target_profile"]))
    with _db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT * FROM missing_approval_episode
               WHERE trace_id=? AND run_id=? AND target_profile=?""",
            key,
        ).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO missing_approval_episode(
                       trace_id,run_id,target_profile,observation_count,first_observed_at,
                       last_observed_at,status,incident_delivery_state,recovery_delivery_state
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (*key, 1, now, now, "observing", "pending", "none"),
            )
        elif str(row["status"]) in {"recovered", "resolved_without_alert"}:
            conn.execute(
                """UPDATE missing_approval_episode
                      SET episode_number=episode_number+1,observation_count=1,
                          first_observed_at=?,last_observed_at=?,status='observing',
                          incident_delivery_state='pending',recovery_delivery_state='none',
                          correlated_request_id='',next_delivery_at=0,delivery_attempts=0,
                          incident_delivered_at=NULL,recovered_at=NULL,recovery_delivered_at=NULL
                    WHERE trace_id=? AND run_id=? AND target_profile=?""",
                (now, now, *key),
            )
        elif float(row["last_observed_at"]) <= now - MISSING_APPROVAL_REOBSERVE_SECONDS:
            conn.execute(
                """UPDATE missing_approval_episode
                      SET observation_count=observation_count+1,last_observed_at=?
                    WHERE trace_id=? AND run_id=? AND target_profile=?""",
                (now, *key),
            )
        conn.execute(
            """UPDATE missing_approval_episode SET status='incident'
                 WHERE trace_id=? AND run_id=? AND target_profile=?
                   AND status='observing' AND observation_count>=?""",
            (*key, MISSING_APPROVAL_CONFIRMATIONS),
        )
        stored = conn.execute(
            """SELECT * FROM missing_approval_episode
               WHERE trace_id=? AND run_id=? AND target_profile=?""",
            key,
        ).fetchone()
    return dict(stored) if stored else {}


def _record_valid_approval_recovery(
    run: dict[str, Any], request_id: str, now: float
) -> dict[str, Any] | None:
    """Resolve only an alerted episode; a pre-alert race produces no recovery alert."""
    key = (str(run["trace_id"]), str(run["run_id"]), str(run["target_profile"]))
    with _db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT * FROM missing_approval_episode
               WHERE trace_id=? AND run_id=? AND target_profile=?""",
            key,
        ).fetchone()
        if row is None:
            return None
        if str(row["status"]) == "observing" or str(row["incident_delivery_state"]) == "pending":
            conn.execute(
                """UPDATE missing_approval_episode
                      SET status='resolved_without_alert',correlated_request_id=?,recovered_at=?
                    WHERE trace_id=? AND run_id=? AND target_profile=?""",
                (request_id, now, *key),
            )
        elif str(row["status"]) == "incident":
            conn.execute(
                """UPDATE missing_approval_episode
                      SET status='recovered',recovery_delivery_state='pending',
                          correlated_request_id=?,recovered_at=?,next_delivery_at=0
                    WHERE trace_id=? AND run_id=? AND target_profile=?""",
                (request_id, now, *key),
            )
        stored = conn.execute(
            """SELECT * FROM missing_approval_episode
               WHERE trace_id=? AND run_id=? AND target_profile=?""",
            key,
        ).fetchone()
    return dict(stored) if stored else None


def _missing_approval_idempotency(row: dict[str, Any], event: str) -> str:
    base = "-".join((
        "missing-approval", event, str(row["trace_id"]), str(row["run_id"]),
        str(row["target_profile"]),
    ))
    if int(row.get("episode_number") or 1) > 1:
        base += f"-{int(row['episode_number'])}"
    if len(base) <= 220 and re.fullmatch(r"[A-Za-z0-9_-]+", base):
        return base
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return f"missing-approval-{event}-{digest}"


def _deliver_missing_approval_event(row: dict[str, Any], event: str, now: float) -> bool:
    """Deliver one redacted Jarvis control signal; never touch the paused target."""
    if event not in {"incident", "recovery"}:
        return False
    state_column = "incident_delivery_state" if event == "incident" else "recovery_delivery_state"
    required_status = "incident" if event == "incident" else "recovered"
    key = (str(row["trace_id"]), str(row["run_id"]), str(row["target_profile"]))
    with _db_connect() as conn:
        claimed = conn.execute(
            f"""UPDATE missing_approval_episode
                   SET {state_column}='delivering',delivery_attempts=delivery_attempts+1,
                       next_delivery_at=?
                 WHERE trace_id=? AND run_id=? AND target_profile=? AND status=?
                   AND {state_column}!='delivered' AND next_delivery_at<=?""",
            (now + RETRY_INTERVAL_SECONDS, *key, required_status, now),
        ).rowcount
    if claimed != 1:
        return False
    endpoint, api_key = _jarvis_route()
    if not endpoint or not api_key:
        with _db_connect() as conn:
            conn.execute(
                f"""UPDATE missing_approval_episode SET {state_column}='pending'
                     WHERE trace_id=? AND run_id=? AND target_profile=?""",
                key,
            )
        return False
    trace_id = _redact_text(row["trace_id"], 200)
    run_id = _redact_text(row["run_id"], 200)
    target = _redact_text(row["target_profile"], 80)
    if event == "incident":
        prompt = (
            "MISSING APPROVAL INCIDENT\n"
            f"trace_id: {trace_id}\nrun_id: {run_id}\ntarget: {target}\n"
            "The authoritative run status was observed waiting_for_approval repeatedly, "
            "but no valid correlation-bound pending_approvals object was present. "
            "Alert only: execution remains blocked. Do not approve, restart a gateway, "
            "start another specialist run, retry the paused command, or reconstruct an approval."
        )
    else:
        request_id = _redact_text(row.get("correlated_request_id"), 200)
        prompt = (
            "MISSING APPROVAL RECOVERED\n"
            f"trace_id: {trace_id}\nrun_id: {run_id}\ntarget: {target}\nrequest_id: {request_id}\n"
            "A valid authoritative approval object now matches the same paused run and the "
            "existing normal approval path has resumed. This is one alert-only all-clear; "
            "it is not an approval decision and authorizes no restart or retry."
        )
    try:
        result = _request(
            f"{endpoint}/v1/runs", api_key, "POST",
            {"input": prompt, "session_id": f"missing-approval:{trace_id}:{run_id}:{target}"},
            idempotency_key=_missing_approval_idempotency(row, event),
        )
        if not result.get("run_id"):
            raise RuntimeError("Jarvis alert delivery returned no run id")
    except Exception:
        with _db_connect() as conn:
            conn.execute(
                f"""UPDATE missing_approval_episode SET {state_column}='pending'
                     WHERE trace_id=? AND run_id=? AND target_profile=?""",
                key,
            )
        return False
    delivered_column = "incident_delivered_at" if event == "incident" else "recovery_delivered_at"
    with _db_connect() as conn:
        conn.execute(
            f"""UPDATE missing_approval_episode
                   SET {state_column}='delivered',{delivered_column}=?
                 WHERE trace_id=? AND run_id=? AND target_profile=?""",
            (now, *key),
        )
    return True


def _prune_missing_approval_episodes(now: float) -> None:
    with _db_connect() as conn:
        conn.execute(
            """DELETE FROM missing_approval_episode
                 WHERE status IN ('recovered','resolved_without_alert')
                   AND last_observed_at<?""",
            (now - MISSING_APPROVAL_RETENTION_SECONDS,),
        )


def _reconcile_once(now: float | None = None) -> dict[str, int]:
    _init_approval_db()
    current = float(now or time.time())
    _repair_final_result_delivery_audit(current)
    _prune_missing_approval_episodes(current)
    counters = {
        "approvals_discovered": 0,
        "notifications_delivered": 0,
        "final_results_delivered": 0,
        "origin_returns_delivered": 0,
        "missing_approval_incidents_delivered": 0,
        "missing_approval_recoveries_delivered": 0,
    }
    routes = _load_routes().get("profiles", {})
    with _db_connect() as conn:
        runs = [dict(row) for row in conn.execute(
            "SELECT * FROM coordination_run WHERE final_delivery_state!='delivered' ORDER BY created_at"
        ).fetchall()]
    for run in runs:
        target_cfg = routes.get(run["target_profile"], {})
        endpoint = str(target_cfg.get("endpoint") or "").rstrip("/")
        key = str(target_cfg.get("api_key") or "")
        if not endpoint or not key:
            continue
        try:
            latest = _request(f"{endpoint}/v1/runs/{run['run_id']}", key, "GET")
        except Exception:
            continue
        status = str(latest.get("status") or run["status"]).lower()
        with _db_connect() as conn:
            conn.execute("UPDATE coordination_run SET status=?,updated_at=? WHERE run_id=?", (status, current, run["run_id"]))
        if status == "waiting_for_approval":
            valid_event = _valid_pending_approval_event(latest, str(run["run_id"]))
            if valid_event is None:
                episode = _observe_missing_approval(run, current)
                if episode and _deliver_missing_approval_event(episode, "incident", current):
                    counters["missing_approval_incidents_delivered"] += 1
                continue
            approval = _queue_from_status(
                latest=latest, trace_id=run["trace_id"], caller=run["calling_profile"],
                target=run["target_profile"], objective=run["objective"],
            )
            if approval:
                recovery = _record_valid_approval_recovery(run, approval["request_id"], current)
                if recovery and _deliver_missing_approval_event(recovery, "recovery", current):
                    counters["missing_approval_recoveries_delivered"] += 1
                with _db_connect() as conn:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM approval_event WHERE request_id=? AND event_type='requested'",
                        (approval["request_id"],),
                    ).fetchone()[0]
                    approval_row = conn.execute(
                        "SELECT * FROM approval_request WHERE request_id=?", (approval["request_id"],)
                    ).fetchone()
                if count == 1:
                    counters["approvals_discovered"] += 1
                if approval_row and approval_row["status"] == "pending" and approval_row["goal_mandate_id"]:
                    lane = _approval_lane(str(approval_row["risk_class"]), bool(approval_row["requires_jan"]))
                    if lane == "auto":
                        _auto_resolve_if_covered(dict(approval_row))
        if status in TERMINAL_STATES:
            refreshed = dict(run)
            refreshed["status"] = status
            output = str(latest.get("output") or latest.get("error") or "")
            if _deliver_final_result(refreshed, status, output, current):
                counters["final_results_delivered"] += 1
            if _deliver_return_to_caller(refreshed, status, output, current):
                counters["origin_returns_delivered"] += 1

    with _db_connect() as conn:
        pending = [dict(row) for row in conn.execute(
            """SELECT * FROM approval_request
               WHERE status IN ('pending','escalated') AND notification_state!='delivered'
                 AND next_notification_at<=? ORDER BY created_at""",
            (current,),
        ).fetchall()]
    for approval in pending:
        if _notify_jarvis(approval, current):
            counters["notifications_delivered"] += 1
    return counters


_RECONCILER_STARTED = False
_RECONCILER_LOCK = threading.Lock()


def _start_reconciler() -> None:
    global _RECONCILER_STARTED
    if _profile_name() != "default":
        return
    with _RECONCILER_LOCK:
        if _RECONCILER_STARTED:
            return
        _RECONCILER_STARTED = True
    def loop() -> None:
        while True:
            try:
                _reconcile_once()
            except Exception:
                pass
            time.sleep(RECONCILE_INTERVAL_SECONDS)
    threading.Thread(target=loop, name="team-approval-reconciler", daemon=True).start()


def _public_approval(row: dict[str, Any] | sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    return {
        "request_id": data["request_id"],
        "trace_id": data["trace_id"],
        "calling_profile": data["calling_profile"],
        "requesting_profile": data["requesting_profile"],
        "paused_run_id": data["paused_run_id"],
        "requested_action": data["requested_action"],
        "tool": data["tool"],
        "description": data["description"],
        "command_preview": data["command_preview"],
        "risk_class": data["risk_class"],
        "requires_jan": bool(data["requires_jan"]),
        "goal_mandate_id": data.get("goal_mandate_id", ""),
        "scope_fingerprint": data.get("scope_fingerprint", ""),
        "status": data["status"],
        "created_at": data["created_at"],
        "expires_at": data["expires_at"],
        "decision": data.get("decision") if isinstance(data, dict) else data["decision"],
    }


def _queue_from_status(
    *,
    latest: dict[str, Any],
    trace_id: str,
    caller: str,
    target: str,
    objective: str,
) -> dict[str, Any] | None:
    expected_run_id = str(latest.get("run_id") or "")
    event = _valid_pending_approval_event(latest, expected_run_id)
    if event is None:
        return None
    request_id = str(event["request_id"])
    pattern_keys = event.get("pattern_keys") or []
    tool = str(pattern_keys[0] if pattern_keys else "terminal")
    # Newer Hermes run-status payloads expose the redacted command as
    # `command_preview`; retain `command` only as a legacy fallback.
    command_preview = str(event.get("command_preview") or event.get("command") or "")
    created_at = float(event.get("timestamp") or time.time())
    risk_class, requires_jan = _classify_approval(
        tool,
        str(event.get("description") or ""),
        command_preview,
    )
    parent_session_id = ""
    with _db_connect() as conn:
        run_row = conn.execute(
            "SELECT parent_session_id FROM coordination_run WHERE run_id=?",
            (str(latest.get("run_id") or event.get("run_id") or ""),),
        ).fetchone()
        if run_row:
            parent_session_id = str(run_row["parent_session_id"] or "")
    row = _store_approval({
        "request_id": request_id,
        "trace_id": trace_id,
        "calling_profile": caller,
        "requesting_profile": target,
        "paused_run_id": str(latest.get("run_id") or event.get("run_id") or ""),
        "parent_session_id": parent_session_id,
        "requested_action": objective,
        "tool": tool,
        "description": event.get("description"),
        "command_preview": command_preview,
        "risk_class": risk_class,
        "requires_jan": requires_jan,
        "created_at": created_at,
        "expires_at": created_at + APPROVAL_TTL_SECONDS,
    })
    return _public_approval(row) if row else None


def _auto_resolve_if_covered(row: dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    lane = _approval_lane(str(record.get("risk_class") or ""), bool(record.get("requires_jan")))
    if not record.get("goal_mandate_id"):
        return {"ok": False, "covered": False, "lane": lane, "status": str(record.get("status") or "")}
    if lane != "auto":
        return {"ok": False, "covered": True, "lane": lane, "status": str(record.get("status") or "")}
    if str(record.get("status") or "") != "pending":
        return {"ok": False, "covered": True, "lane": lane, "error": "approval is not pending", "status": record.get("status")}
    with _db_connect() as conn:
        conn.execute(
            "UPDATE approval_request SET notification_state='suppressed_by_mandate' WHERE request_id=? AND status='pending'",
            (str(record["request_id"]),),
        )
        _audit(conn, str(record["request_id"]), "mandate_internal_approval", "jarvis", str(record["goal_mandate_id"]))
    return json.loads(respond_team_approval({
        "request_id": str(record["request_id"]),
        "decision": "allow-once",
    }))


def list_team_approvals(args: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    if _profile_name() != "default":
        return json.dumps({"ok": False, "error": "Jarvis approval router only"})
    _init_approval_db()
    status = str(args.get("status") or "pending")
    try:
        limit = max(1, min(int(args.get("limit", 50)), 100))
    except (TypeError, ValueError):
        limit = 50
    now = time.time()
    with _db_connect() as conn:
        expired = conn.execute(
            "SELECT request_id FROM approval_request WHERE status='pending' AND expires_at<=?",
            (now,),
        ).fetchall()
        for row in expired:
            conn.execute(
                "UPDATE approval_request SET status='expired',decision='deny',decided_at=?,decision_actor='timeout' WHERE request_id=? AND status='pending'",
                (now, row["request_id"]),
            )
            _audit(conn, row["request_id"], "expired", "timeout")
        if status == "all":
            rows = conn.execute(
                "SELECT * FROM approval_request ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM approval_request WHERE status=? ORDER BY created_at LIMIT ?",
                (status, limit),
            ).fetchall()
    approvals = [_public_approval(row) for row in rows]
    return json.dumps({"ok": True, "count": len(approvals), "approvals": approvals})


def respond_team_approval(args: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    if _profile_name() != "default":
        return json.dumps({"ok": False, "error": "Jarvis approval router only"})
    request_id = str(args.get("request_id") or "").strip()
    decision = str(args.get("decision") or "").strip()
    if not REQUEST_RE.fullmatch(request_id) or decision not in {"allow-once", "deny", "escalate-to-Jan"}:
        return json.dumps({"ok": False, "error": "invalid request_id or decision"})
    _init_approval_db()
    now = time.time()
    with _db_connect() as conn:
        requested = conn.execute("SELECT * FROM approval_request WHERE request_id=?", (request_id,)).fetchone()
        if requested is None:
            return json.dumps({"ok": False, "error": "approval not found"})
        requested_record = dict(requested)
        canonical_request_id = str(requested_record.get("canonical_request_id") or request_id)
        canonical = conn.execute(
            "SELECT * FROM approval_request WHERE request_id=?", (canonical_request_id,)
        ).fetchone()
        if canonical is None:
            return json.dumps({"ok": False, "error": "canonical approval not found"})
        record = dict(canonical)
        if float(record["expires_at"]) <= now and record["status"] == "pending":
            conn.execute(
                """UPDATE approval_request SET status='expired',decision='deny',decided_at=?,decision_actor='timeout'
                   WHERE request_id=? OR canonical_request_id=?""",
                (now, canonical_request_id, canonical_request_id),
            )
            _audit(conn, canonical_request_id, "expired", "timeout")
            return json.dumps({"ok": False, "error": "approval expired"})
        if decision == "allow-once" and bool(record["requires_jan"]):
            _audit(conn, canonical_request_id, "jan_escalation_required", "jarvis", record["risk_class"])
            return json.dumps({
                "ok": False, "error": "approval requires Jan", "risk_class": record["risk_class"],
                "request_id": canonical_request_id,
            })
        group = [dict(row) for row in conn.execute(
            """SELECT * FROM approval_request
               WHERE request_id=? OR canonical_request_id=? ORDER BY created_at,request_id""",
            (canonical_request_id, canonical_request_id),
        ).fetchall()]
        if decision == "escalate-to-Jan":
            if record["status"] != "pending":
                return json.dumps({"ok": False, "error": "approval is not pending", "status": record["status"]})
            conn.execute(
                """UPDATE approval_request SET status='escalated',decision=?,decided_at=?,decision_actor='jarvis'
                   WHERE (request_id=? OR canonical_request_id=?) AND status IN ('pending','delivery_failed')""",
                (decision, now, canonical_request_id, canonical_request_id),
            )
            _audit(conn, canonical_request_id, "escalated_to_jan", "jarvis")
            packet = {
                "packet_type": "decision_packet", "request_id": canonical_request_id,
                "linked_request_ids": [row["request_id"] for row in group],
                "trace_id": record["trace_id"], "paused_run_id": record["paused_run_id"],
                "requested_action": record["requested_action"], "risk_class": record["risk_class"],
                "recommendation": "Jan decides allow or deny; all exactly linked specialist runs remain paused.",
                "required_approval": "Jan", "safety_state": "no action executed",
            }
            return json.dumps({"ok": True, "request_id": canonical_request_id, "status": "escalated", "decision_packet": packet})
        retrying_same_decision = (
            record["status"] in {"consumed", "denied"} and str(record.get("decision") or "") == decision
        )
        if record["status"] != "pending" and not retrying_same_decision:
            return json.dumps({"ok": False, "error": "approval is not pending", "status": record["status"]})
        eligible = [row for row in group if row["status"] in {"pending", "delivery_failed"}]
        if not eligible:
            return json.dumps({"ok": False, "error": "approval is not pending", "status": record["status"]})
        for row in eligible:
            changed = conn.execute(
                """UPDATE approval_request SET status='delivering',decision=?,decided_at=?,decision_actor='jarvis'
                   WHERE request_id=? AND status IN ('pending','delivery_failed')""",
                (decision, now, row["request_id"]),
            ).rowcount
            if changed == 1:
                _audit(conn, row["request_id"], "decision_made", "jarvis", decision)

    routes = _load_routes().get("profiles", {})
    choice = "once" if decision == "allow-once" else "deny"
    final_status = "consumed" if decision == "allow-once" else "denied"
    delivered_request_ids: list[str] = []
    failed_request_ids: list[str] = []
    for native in eligible:
        native_request_id = str(native["request_id"])
        target = str(native["requesting_profile"])
        target_cfg = routes.get(target, {})
        endpoint = str(target_cfg.get("endpoint") or "").rstrip("/")
        key = str(target_cfg.get("api_key") or "")
        failure = "route unavailable"
        result: dict[str, Any] = {}
        if endpoint and key:
            try:
                result = _request(
                    f"{endpoint}/v1/runs/{native['paused_run_id']}/approval", key, "POST",
                    {"choice": choice, "request_id": native_request_id},
                    idempotency_key=f"approval-decision-{native_request_id}",
                )
                failure = "correlation failed"
            except Exception:
                result = {}
                failure = "target unavailable"
        correlated = (
            str(result.get("request_id") or "") == native_request_id
            and int(result.get("resolved") or 0) > 0
            and str(result.get("choice") or "") == choice
        )
        with _db_connect() as conn:
            if not correlated:
                conn.execute(
                    "UPDATE approval_request SET status='delivery_failed' WHERE request_id=? AND status='delivering'",
                    (native_request_id,),
                )
                _audit(conn, native_request_id, "decision_delivery_failed", "jarvis", failure)
                failed_request_ids.append(native_request_id)
                continue
            completed_at = time.time()
            conn.execute(
                "UPDATE approval_request SET status=?,consumed_at=?,resume_state=? WHERE request_id=? AND status='delivering'",
                (final_status, completed_at, "resumed" if decision == "allow-once" else "denied", native_request_id),
            )
            conn.execute(
                "UPDATE coordination_run SET status=?,resume_state=?,updated_at=? WHERE run_id=?",
                ("running" if decision == "allow-once" else "denied",
                 "resumed" if decision == "allow-once" else "denied", completed_at, native["paused_run_id"]),
            )
            _audit(conn, native_request_id, "decision_delivered_to_paused_run", "jarvis", decision)
            _audit(conn, native_request_id, "run_resumed_or_denied", target, final_status)
            delivered_request_ids.append(native_request_id)
    return json.dumps({
        "ok": not failed_request_ids, "request_id": canonical_request_id,
        "status": final_status if not failed_request_ids else "delivery_failed",
        "decision": decision, "delivered_request_ids": delivered_request_ids,
        "failed_request_ids": failed_request_ids,
    })


def _parse_datetime(value: Any) -> datetime:
    text = str(value or "").strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed.astimezone(timezone.utc)


def _development_error(code: str, reason: str) -> dict[str, Any]:
    return {"ok": False, "error_code": code, "error": reason}


def _validate_candidate_manifest(value: Any) -> tuple[dict[str, Any] | None, str | None, str | None]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "artifact_sha256", "source_manifest_sha256", "manifest_sha256",
    }:
        return None, None, "candidate manifest has an invalid field set"
    if value.get("schema_version") != "1.0":
        return None, None, "candidate manifest schema version is invalid"
    artifact_digest = str(value.get("artifact_sha256") or "")
    source_manifest_digest = str(value.get("source_manifest_sha256") or "")
    manifest_digest = str(value.get("manifest_sha256") or "")
    if not all(SHA256_RE.fullmatch(item) for item in (artifact_digest, source_manifest_digest, manifest_digest)):
        return None, None, "candidate manifest digest is invalid"
    unsigned = {key: item for key, item in value.items() if key != "manifest_sha256"}
    if manifest_digest != _canonical_fingerprint(unsigned):
        return None, None, "candidate manifest self-digest mismatch"
    return value, manifest_digest, None


def _load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _capsule_contains_secret(capsule: dict[str, Any]) -> bool:
    canonical = json.dumps(capsule, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return len(canonical) > 100_000 or bool(SECRET_VALUE_RE.search(canonical))


def _validate_development_route_binding(
    target_cfg: dict[str, Any], profiles: dict[str, Any], admission: dict[str, Any]
) -> str | None:
    target = admission["target"]
    phase = admission["phase"]
    expected_host = DEFAULT_DEVELOPMENT_HOST if phase == "qa" else admission["run_host"]
    expected_role = "qa" if phase == "qa" else "developer"
    expected_access = "read-only" if phase == "qa" else "isolated-worktree-write"
    endpoint = urllib.parse.urlparse(str(target_cfg.get("endpoint") or ""))
    if endpoint.scheme != "http" or endpoint.hostname not in {"127.0.0.1", "localhost"}:
        return "development route endpoint is not loopback-only"
    if (
        str(target_cfg.get("run_host") or "") != expected_host
        or str(target_cfg.get("network_route") or "") != admission["network_route"]
        or str(target_cfg.get("role") or "") != expected_role
        or str(target_cfg.get("candidate_access") or "") != expected_access
    ):
        return "development route host, network route, role, or candidate custody binding mismatch"
    developer_cfg = profiles.get("developer136") or {}
    qa_cfg = profiles.get("qa136") or {}
    if (
        not developer_cfg.get("api_key") or not qa_cfg.get("api_key")
        or developer_cfg.get("api_key") == qa_cfg.get("api_key")
        or developer_cfg.get("endpoint") == qa_cfg.get("endpoint")
    ):
        return "Developer and QA route identities are not separate"
    if target != admission["target"]:
        return "development target changed after admission"
    return None


def _validate_placement_exception(
    capsule: dict[str, Any], development: dict[str, Any], now: datetime
) -> tuple[bool, str | None]:
    run_host = str(development.get("requested_run_host") or "")
    exception_id = capsule.get("task", {}).get("placement_exception_id")
    if run_host == DEFAULT_DEVELOPMENT_HOST:
        if exception_id:
            return False, "placement exception is not valid for the default development host"
        return True, None
    if not exception_id:
        return False, "non-136 development requires an active exact placement exception"
    try:
        registry = _load_json_object(DEVELOPMENT_EXCEPTIONS_PATH)
    except Exception:
        return False, "placement exception registry is unavailable or invalid"
    project = capsule.get("project", {})
    names = {str(project.get("project_id") or ""), str(project.get("name") or "")}
    names.update(str(item) for item in project.get("aliases") or [])
    repository = str(project.get("repository") or "")
    route = str(development.get("network_route") or "")
    target_environment = str(capsule.get("task", {}).get("target_environment") or "")
    for item in registry.get("exceptions") or []:
        if not isinstance(item, dict) or str(item.get("exception_id") or "") != str(exception_id):
            continue
        try:
            valid_from = _parse_datetime(item.get("valid_from"))
            expires_at = _parse_datetime(item.get("expires_at"))
        except Exception:
            return False, "placement exception validity window is incomplete"
        exact = (
            item.get("status") == "active"
            and str(item.get("project") or "") in names
            and str(item.get("approved_run_host") or "") == run_host
            and str(item.get("network_route") or "") == route
            and str(item.get("target_profile") or "") == str(development.get("exception_target_profile") or "")
            and valid_from <= now < expires_at
            and repository in set(item.get("allowed_repositories") or [])
            and target_environment in set(item.get("allowed_targets") or [])
            and bool(item.get("credential_boundary"))
            and bool(item.get("qa_route"))
            and bool(item.get("kill_switch"))
        )
        return (True, None) if exact else (False, "placement exception is incomplete, expired, or not an exact project/host/route match")
    return False, "placement exception was not found"


def _validate_development_admission(
    caller: str, target: str, objective: str, context: str, development: Any
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if caller != "default":
        return None, _development_error("development_context_denied", "development profiles are admitted only by Jarvis")
    if not isinstance(development, dict):
        return None, _development_error("development_context_denied", "structured development_context is required")
    if context:
        return None, _development_error("development_context_denied", "free-text context is forbidden for developer136/qa136")
    phase = str(development.get("phase") or "")
    run_host = str(development.get("requested_run_host") or "")
    if phase == "qa":
        expected_target = "qa136"
    elif phase == "developer" and run_host == DEFAULT_DEVELOPMENT_HOST:
        expected_target = "developer136"
    elif phase == "developer":
        expected_target = str(development.get("exception_target_profile") or target or "")
    else:
        expected_target = ""
    if not expected_target or not PROFILE_RE.fullmatch(expected_target):
        return None, _development_error("development_context_denied", "development phase must be developer or qa")
    if target and target != expected_target:
        return None, _development_error("development_placement_denied", "target profile does not match the structured development phase")
    capsule = development.get("capsule")
    if not isinstance(capsule, dict):
        return None, _development_error("development_context_denied", "Context Capsule is required")
    if _capsule_contains_secret(capsule):
        return None, _development_error("development_context_denied", "Context Capsule is oversized or contains secret-shaped data")
    try:
        schema = _load_json_object(DEVELOPMENT_CAPSULE_SCHEMA_PATH)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(capsule),
            key=lambda error: list(error.absolute_path),
        )
    except Exception:
        return None, _development_error("development_context_denied", "Context Capsule schema is unavailable or invalid")
    if errors:
        return None, _development_error("development_context_denied", f"Context Capsule schema validation failed at {'.'.join(map(str, errors[0].absolute_path)) or '<root>'}")
    if capsule.get("developer_profile") != "developer136" or capsule.get("qa_profile") != "qa136":
        return None, _development_error("development_context_denied", "Context Capsule profile pair is invalid")
    task = capsule["task"]
    if objective != str(task.get("objective") or ""):
        return None, _development_error("development_context_denied", "objective does not match the hashed task brief")
    capsule_hash = _canonical_fingerprint(capsule)
    if str(development.get("capsule_sha256") or "") != capsule_hash:
        return None, _development_error("development_context_denied", "Context Capsule hash mismatch")
    world = capsule["world_system"]
    if (
        world.get("entity_id") != capsule["customer"]["entity_id"]
        or world.get("canonical_name") != capsule["customer"]["canonical_name"]
        or world.get("project_id") != capsule["project"]["project_id"]
        or world.get("project_name") != capsule["project"]["name"]
        or world.get("project_aliases") != capsule["project"].get("aliases", [])
        or len(world.get("facts") or []) > 25
    ):
        return None, _development_error("development_context_denied", "World System customer/project identity is ambiguous, cross-project, or not least-context")
    world_hash = _canonical_fingerprint({key: value for key, value in world.items() if key != "snapshot_sha256"})
    if world.get("snapshot_sha256") != world_hash or development.get("world_system_sha256") != world_hash:
        return None, _development_error("development_context_denied", "World System snapshot hash mismatch")
    artifacts = capsule["context_artifacts"]
    required_artifacts = {
        "project_context_sha256", "task_brief_sha256", "permission_envelope_sha256",
        "workflow_data_manifest_sha256", "architecture_sha256", "acceptance_sha256",
    }
    if not required_artifacts.issubset(artifacts) or not all(SHA256_RE.fullmatch(str(artifacts[key])) for key in required_artifacts):
        return None, _development_error("development_context_denied", "required context artifact hashes are missing or invalid")
    if artifacts["project_context_sha256"] != _canonical_fingerprint({"customer": capsule["customer"], "project": capsule["project"]}):
        return None, _development_error("development_context_denied", "project/customer context hash mismatch")
    if artifacts["task_brief_sha256"] != _canonical_fingerprint(task):
        return None, _development_error("development_context_denied", "task brief hash mismatch")
    if artifacts["acceptance_sha256"] != _canonical_fingerprint(task["acceptance_criteria"]):
        return None, _development_error("development_context_denied", "acceptance criteria hash mismatch")
    policy_versions = capsule.get("policy_versions") or {}
    if policy_versions != DEVELOPMENT_POLICY_HASHES or not all(SHA256_RE.fullmatch(value) for value in DEVELOPMENT_POLICY_HASHES.values()):
        return None, _development_error("development_context_denied", "policy/context/schema hash binding is stale or invalid")
    now = datetime.now(timezone.utc)
    try:
        created = _parse_datetime(capsule["created_at"])
        capsule_expiry = _parse_datetime(capsule["expires_at"])
        world_retrieved = _parse_datetime(world["retrieved_at"])
        world_status = _parse_datetime(world["status_checked_at"])
        world_expiry = _parse_datetime(world["expires_at"])
    except Exception:
        return None, _development_error("development_context_denied", "capsule or World System timestamps are invalid")
    if created > now or world_retrieved > now or world_status > now or now >= capsule_expiry or now >= world_expiry:
        return None, _development_error("development_context_denied", "capsule or World System context is missing, future-dated, or expired")
    if capsule_expiry > created + timedelta(hours=24) or world_expiry > world_retrieved + timedelta(hours=24):
        return None, _development_error("development_context_denied", "capsule or World System validity exceeds 24 hours")
    required_connectors = development.get("required_connectors")
    if not isinstance(required_connectors, list) or not required_connectors:
        return None, _development_error("development_context_denied", "required World System connectors must be declared")
    connectors = {str(item.get("name") or ""): item for item in world.get("connectors") or [] if isinstance(item, dict)}
    for name in required_connectors:
        connector = connectors.get(str(name))
        try:
            last_sync = _parse_datetime(connector.get("last_successful_sync")) if connector else None
        except Exception:
            last_sync = None
        if not connector or connector.get("status") != "enabled" or last_sync is None or now - last_sync > timedelta(hours=24):
            return None, _development_error("development_context_denied", f"required World System connector is missing, disabled, or stale: {name}")
    placement_ok, placement_error = _validate_placement_exception(capsule, development, now)
    if not placement_ok:
        return None, _development_error("development_placement_denied", str(placement_error))
    admission = {
        "phase": phase,
        "target": expected_target,
        "project_id": str(capsule["project"]["project_id"]),
        "run_host": run_host,
        "network_route": str(development.get("network_route") or ""),
        "capsule": capsule,
        "capsule_sha256": capsule_hash,
        "world_system_sha256": world_hash,
        "acceptance_sha256": str(artifacts["acceptance_sha256"]),
        "candidate_artifact_digest": None,
        "candidate_manifest_sha256": None,
        "candidate_manifest_json": None,
        "developer_trace_id": None,
    }
    candidate_manifest = task.get("candidate_manifest")
    if candidate_manifest is not None:
        candidate_manifest, manifest_digest, manifest_error = _validate_candidate_manifest(candidate_manifest)
        if manifest_error:
            return None, _development_error("development_context_denied", manifest_error)
        assert candidate_manifest is not None and manifest_digest is not None
        task_digest = task.get("candidate_artifact_digest")
        if task_digest is not None and str(task_digest) != candidate_manifest["artifact_sha256"]:
            return None, _development_error("development_context_denied", "task and candidate manifest artifact digests differ")
        admission["candidate_artifact_digest"] = candidate_manifest["artifact_sha256"]
        admission["candidate_manifest_sha256"] = manifest_digest
        admission["candidate_manifest_json"] = json.dumps(candidate_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if phase == "qa":
        if "candidate_read_only" in development:
            return None, _development_error("development_context_denied", "candidate custody is derived from the trusted Developer record")
        candidate_digest = str(development.get("candidate_artifact_digest") or "")
        developer_trace_id = str(development.get("developer_trace_id") or "")
        if not SHA256_RE.fullmatch(candidate_digest) or not developer_trace_id:
            return None, _development_error("development_context_denied", "QA requires an exact SHA-256 candidate digest and developer trace")
        _init_approval_db()
        with _db_connect() as conn:
            developer_row = conn.execute(
                "SELECT * FROM development_admission WHERE trace_id=? AND phase='developer'",
                (developer_trace_id,),
            ).fetchone()
        if not developer_row:
            return None, _development_error("development_context_denied", "bound developer admission was not found")
        parity = (
            str(developer_row["project_id"]) == admission["project_id"]
            and str(developer_row["run_host"]) == admission["run_host"]
            and str(developer_row["capsule_sha256"]) == capsule_hash
            and str(developer_row["world_system_sha256"]) == world_hash
            and str(developer_row["acceptance_sha256"]) == admission["acceptance_sha256"]
        )
        if not parity:
            return None, _development_error("development_context_denied", "Developer/QA capsule, World System, project, host, or acceptance hash parity failed")
        try:
            stored_manifest = json.loads(str(developer_row["candidate_manifest_json"] or ""))
        except json.JSONDecodeError:
            stored_manifest = None
        stored_manifest, stored_manifest_digest, stored_manifest_error = _validate_candidate_manifest(stored_manifest)
        if (
            stored_manifest_error
            or not stored_manifest
            or candidate_digest != str(developer_row["candidate_artifact_digest"] or "")
            or stored_manifest_digest != str(developer_row["candidate_manifest_sha256"] or "")
        ):
            return None, _development_error("development_context_denied", "QA candidate is not the immutable Developer-produced record")
        if candidate_manifest and candidate_manifest != stored_manifest:
            return None, _development_error("development_context_denied", "QA candidate manifest differs from the immutable Developer-produced record")
        admission["candidate_artifact_digest"] = candidate_digest
        admission["candidate_manifest_sha256"] = stored_manifest_digest
        admission["candidate_manifest_json"] = json.dumps(
            stored_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        admission["developer_trace_id"] = developer_trace_id
    return admission, None


def _store_development_admission(admission: dict[str, Any], trace_id: str, run_id: str) -> None:
    _init_approval_db()
    with _db_connect() as conn:
        conn.execute(
            """INSERT INTO development_admission(
                trace_id,run_id,phase,project_id,run_host,target_profile,capsule_sha256,
                world_system_sha256,acceptance_sha256,candidate_artifact_digest,candidate_manifest_sha256,
                candidate_manifest_json,developer_trace_id,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                trace_id, run_id, admission["phase"], admission["project_id"], admission["run_host"],
                admission["target"], admission["capsule_sha256"], admission["world_system_sha256"],
                admission["acceptance_sha256"], admission.get("candidate_artifact_digest"),
                admission.get("candidate_manifest_sha256"), admission.get("candidate_manifest_json"),
                admission.get("developer_trace_id"), time.time(),
            ),
        )


def _bind_terminal_developer_candidate(trace_id: str, output: Any) -> dict[str, Any]:
    try:
        payload = json.loads(str(output or ""))
        evidence = payload["implementation_evidence"]
        manifest = evidence["candidate_manifest"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    manifest, manifest_digest, error = _validate_candidate_manifest(manifest)
    if error or manifest is None or manifest_digest is None:
        raise ValueError(error or "terminal candidate manifest is invalid")
    manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    artifact_digest = manifest["artifact_sha256"]
    with _db_connect() as conn:
        row = conn.execute(
            "SELECT phase,candidate_artifact_digest,candidate_manifest_sha256,candidate_manifest_json "
            "FROM development_admission WHERE trace_id=?",
            (trace_id,),
        ).fetchone()
        if not row or str(row["phase"]) != "developer":
            raise ValueError("terminal candidate has no matching Developer admission")
        existing = (
            str(row["candidate_artifact_digest"] or ""),
            str(row["candidate_manifest_sha256"] or ""),
            str(row["candidate_manifest_json"] or ""),
        )
        candidate = (artifact_digest, manifest_digest, manifest_json)
        if any(existing) and existing != candidate:
            raise ValueError("terminal candidate replay diverges from the immutable Developer admission")
        conn.execute(
            """UPDATE development_admission
                  SET candidate_artifact_digest=?,candidate_manifest_sha256=?,candidate_manifest_json=?
                WHERE trace_id=? AND phase='developer'
                  AND (candidate_artifact_digest IS NULL OR candidate_artifact_digest=?)
                  AND (candidate_manifest_sha256 IS NULL OR candidate_manifest_sha256=?)
                  AND (candidate_manifest_json IS NULL OR candidate_manifest_json=?)""",
            (artifact_digest, manifest_digest, manifest_json, trace_id, artifact_digest, manifest_digest, manifest_json),
        )
        if conn.total_changes != 1:
            raise ValueError("terminal candidate compare-and-set failed")
    return {
        "candidate_artifact_digest": artifact_digest,
        "candidate_manifest_sha256": manifest_digest,
    }


def coordinate_agent(args: dict[str, Any], **kwargs: Any) -> str:
    caller = _profile_name()
    parent_session_id = str(kwargs.get("session_id") or kwargs.get("task_id") or "")
    target = str(args.get("target") or "").strip().lower()
    objective = _safe_text(args.get("objective"), MAX_TASK_CHARS).strip()
    context = _safe_text(args.get("context"), MAX_TASK_CHARS).strip()
    result_format = _safe_text(args.get("result_format") or "concise specialist report", 300).strip()
    try:
        wait_seconds = max(0, min(int(args.get("wait_seconds", 90)), MAX_WAIT_SECONDS))
    except (TypeError, ValueError):
        wait_seconds = 90

    development = args.get("development_context")
    development_requested = target in DEVELOPMENT_PROFILES or development is not None
    admission: dict[str, Any] | None = None
    if development_requested:
        admission, error = _validate_development_admission(caller, target, objective, context, development)
        if error:
            return json.dumps(error)
        assert admission is not None
        target = admission["target"]

    if not PROFILE_RE.fullmatch(target) or not objective:
        return json.dumps({"ok": False, "error": "target and objective are required"})

    routes = _load_routes()
    profiles = routes.get("profiles", {})
    caller_cfg = profiles.get(caller, {})
    target_cfg = profiles.get(target, {})
    if target not in set(caller_cfg.get("allowed_targets", [])):
        return json.dumps({"ok": False, "error": "target is not authorised for this calling profile"})
    if admission:
        route_error = _validate_development_route_binding(target_cfg, profiles, admission)
        if route_error:
            return json.dumps(_development_error("development_route_denied", route_error))
    endpoint = str(target_cfg.get("endpoint") or "").rstrip("/")
    key = str(target_cfg.get("api_key") or "")
    if not endpoint or not key:
        return json.dumps({"ok": False, "error": "target API route is unavailable"})

    trace_id = f"a2a-{caller}-{target}-{uuid.uuid4().hex[:12]}"
    if admission:
        structured = {
            "phase": admission["phase"],
            "run_host": admission["run_host"],
            "capsule_sha256": admission["capsule_sha256"],
            "world_system_sha256": admission["world_system_sha256"],
            "acceptance_sha256": admission["acceptance_sha256"],
            "candidate_artifact_digest": admission.get("candidate_artifact_digest"),
            "candidate_custody": "read-only" if admission["phase"] == "qa" else "isolated-worktree-write-only; no deployment authority",
            "context_capsule": admission["capsule"],
        }
        verified_context = "Structured development admission (canonical JSON): " + json.dumps(
            structured, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    else:
        verified_context = context or "[none supplied]"
    prompt = (
        "You are a specialist Hermes profile participating in a controlled direct coordination call.\n"
        f"Trace ID: {trace_id}\n"
        f"Calling profile: {caller}\n"
        f"Objective: {objective}\n"
        f"Verified context: {verified_context}\n"
        f"Required result format: {result_format}\n\n"
        "Rules: stay within your role and permissions; do not call external systems or make changes unless the request "
        "explicitly grants that scope and your own profile permits it; do not expose secrets; distinguish facts from "
        "assumptions; return a concise, decision-ready result with risks and next safe action."
    )
    try:
        created = _request(
            f"{endpoint}/v1/runs",
            key,
            "POST",
            {"input": prompt, "session_id": trace_id},
        )
    except urllib.error.HTTPError as exc:
        return json.dumps({"ok": False, "error": f"target API rejected the request ({exc.code})"})
    except Exception:
        return json.dumps({"ok": False, "error": "target API is unavailable"})

    run_id = str(created.get("run_id") or "")
    if not run_id:
        return json.dumps({"ok": False, "error": "target API did not return a run id"})
    _store_coordination_run({
        "run_id": run_id,
        "trace_id": trace_id,
        "calling_profile": caller,
        "target_profile": target,
        "parent_session_id": parent_session_id,
        "objective": objective,
        "status": str(created.get("status") or "started"),
        "created_at": time.time(),
    })
    development_result: dict[str, Any] = {}
    if admission:
        _store_development_admission(admission, trace_id, run_id)
        development_result = {
            "run_host": admission["run_host"],
            "capsule_sha256": admission["capsule_sha256"],
            "world_system_sha256": admission["world_system_sha256"],
            "acceptance_sha256": admission["acceptance_sha256"],
            "candidate_artifact_digest": admission.get("candidate_artifact_digest"),
            "developer_trace_id": admission.get("developer_trace_id"),
        }
    deadline = time.monotonic() + wait_seconds
    latest: dict[str, Any] = {"status": "started", "run_id": run_id}
    while time.monotonic() < deadline:
        try:
            latest = _request(f"{endpoint}/v1/runs/{run_id}", key, "GET")
        except Exception:
            return json.dumps({"ok": False, "run_id": run_id, "trace_id": trace_id, "error": "run started but status is unavailable"})
        status = str(latest.get("status") or "").lower()
        if status == "waiting_for_approval":
            approval = _queue_from_status(
                latest=latest,
                trace_id=trace_id,
                caller=caller,
                target=target,
                objective=objective,
            )
            if approval is None:
                return json.dumps({
                    "ok": False,
                    "trace_id": trace_id,
                    "target": target,
                    "run_id": run_id,
                    "status": status,
                    "error": "target paused without a correlated approval object; execution remains blocked",
                })
            with _db_connect() as conn:
                approval_row = conn.execute(
                    "SELECT * FROM approval_request WHERE request_id=?", (approval["request_id"],)
                ).fetchone()
            record = dict(approval_row) if approval_row else {}
            lane = _approval_lane(str(record.get("risk_class") or ""), bool(record.get("requires_jan")))
            if record.get("goal_mandate_id") and lane == "auto":
                resolved = _auto_resolve_if_covered(record)
                if resolved.get("ok"):
                    latest = {"run_id": run_id, "status": "running"}
                    continue
                return json.dumps({
                    "ok": False, "trace_id": trace_id, "target": target, "run_id": run_id,
                    "status": "reconciliation_required", "approval": approval,
                    "error": "mandated approval outcome is uncertain; no replacement prompt was created",
                })
            notified = bool(approval_row and _notify_jarvis(record, time.time()))
            return json.dumps({
                "ok": False,
                "requires_approval": True,
                "trace_id": trace_id,
                "target": target,
                "run_id": run_id,
                "status": status,
                "approval": approval,
                "active_notification": notified,
                "message": "Formal approval request persisted and actively routed to Jarvis; the specialist remains paused.",
                **development_result,
            })
        if status in TERMINAL_STATES:
            terminal_candidate: dict[str, Any] = {}
            if admission and admission["phase"] == "developer" and status == "completed":
                try:
                    terminal_candidate = _bind_terminal_developer_candidate(trace_id, latest.get("output"))
                except ValueError as exc:
                    return json.dumps({
                        "ok": False,
                        "trace_id": trace_id,
                        "target": target,
                        "run_id": run_id,
                        "status": "reconciliation_required",
                        "error": _safe_text(exc, 500),
                        **development_result,
                    })
                development_result.update(terminal_candidate)
            return json.dumps({
                "ok": status == "completed",
                "trace_id": trace_id,
                "target": target,
                "run_id": run_id,
                "status": status,
                "result": _safe_text(latest.get("output") or latest.get("error") or ""),
                **development_result,
            })
        time.sleep(1.25)
    return json.dumps({
        "ok": True,
        "trace_id": trace_id,
        "target": target,
        "run_id": run_id,
        "status": str(latest.get("status") or "running"),
        "message": "Run is still active; use the run id only for a later controlled follow-up.",
        **development_result,
    })
