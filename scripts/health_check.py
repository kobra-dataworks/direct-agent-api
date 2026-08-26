#!/usr/bin/env python3
"""
direct-agent-api coordinator health check
==========================================
Purpose: prove bot-to-bot communication cannot silently get stuck on a
server by (a) verifying every endpoint in direct-agent-api-routes.json is
reachable, and (b) counting delivery-failure rows in coordination_run.

This is the *actor* layer's health monitor. It must NOT be coupled to the
agent-intelligence observer; it only writes to a JSON report the observer
reads (see CONTRACT.md, §2 "Read-only access").

Usage
-----
    python3 scripts/health_check.py            # human-readable summary + JSON
    python3 scripts/health_check.py --json     # only JSON
    python3 scripts/health_check.py --fail-on-unreachable
    python3 scripts/health_check.py --warn-seconds=30 --fail-seconds=120

Exit codes
----------
    0  all endpoints reachable and no stuck deliveries
    2  one or more endpoints unreachable
    3  one or more stuck deliveries (beyond warn threshold)
    4  configuration / runtime error (bad JSON, unreadable DB, ...)

Endpoints discovered by the same order the plugin uses (see
tools.py around the routes.json loader):
    1. ~/.hermes/direct-agent-api-routes.json
    2. <plugin dir>/direct-agent-api-routes.json  (~/.hermes/plugins/direct-agent-api/)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import socket
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- config ----------------------------------------------------------------

DEFAULT_TIMEOUT_SECONDS = 3.0            # per-endpoint TCP connect timeout
DEFAULT_DB_PATH = os.path.expanduser("~/.hermes/team-coordination.db")
REPORT_PATH = os.path.expanduser(
    "~/.hermes/plugins/direct-agent-api/.health-report.json"
)

# Column names (from the coordination_run schema in tools.py). Kept as a
# single source of truth so the script never drifts from the schema.
FAILURE_COLUMNS = (
    "final_delivery_state",
    "final_result_delivery_state",
    "final_return_delivery_state",
)

# States that count as "still stuck" (a delivery never succeeded).
SUCCESS_STATES = {"success", "confirmed", "ok", "delivered", "done"}


# --- data model ------------------------------------------------------------


@dataclass
class EndpointStatus:
    route_profile: str
    target: str
    reachable: bool = False
    latency_ms: float | None = None
    reason: str = ""


@dataclass
class DeliveryFailure:
    run_id: str
    target_profile: str
    stuck_columns: tuple  # e.g. ("final_result_delivery_state", "pending")
    last_updated: float | None = None


@dataclass
class HealthReport:
    hostname: str
    db_path: str
    routes_path: str
    generated_at: str
    generated_at_ts: float | None = None
    endpoints: list[EndpointStatus] = field(default_factory=list)
    stuck_deliveries: list[DeliveryFailure] = field(default_factory=list)

    @property
    def all_reachable(self) -> bool:
        return bool(self.endpoints) and all(
            e.reachable for e in self.endpoints
        )

    @property
    def total_unreachable(self) -> int:
        return sum(1 for e in self.endpoints if not e.reachable)

    @property
    def total_stuck(self) -> int:
        return len(self.stuck_deliveries)


# --- discovery: same order the plugin uses ---------------------------------


def find_routes_path() -> str | None:
    """Return the first existing routes.json (same search order as the plugin)."""
    candidates = [
        os.path.expanduser("~/.hermes/direct-agent-api-routes.json"),
        os.path.expanduser(
            "~/.hermes/plugins/direct-agent-api/direct-agent-api-routes.json"
        ),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    # Fallback: glob (plugin also falls back to a glob).
    matches = glob.glob(
        os.path.expanduser("~/.hermes/**/direct-agent-api-routes.json"),
        recursive=True,
    )
    return matches[0] if matches else None


def load_routes(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# --- endpoint checks -------------------------------------------------------


def check_endpoint(
    route_profile: str, target: str
) -> EndpointStatus:
    """Connect to host:port; measure TCP connect latency. host:port may be
    'profile@host:port' or 'host:port' (matching the plugin's routing)."""
    status = EndpointStatus(route_profile=route_profile, target=target)
    if "@" in target:
        # <profile>@<host>:port  ->  strip profile for the socket check.
        _, rest = target.split("@", 1)
    else:
        rest = target
    if rest.startswith("http://"):
        rest = rest[len("http://"):]
    host, _, port = rest.rpartition(":")
    host = host or "127.0.0.1"
    if not port:
        status.reason = "malformed endpoint (no port)"
        return status
    try:
        port_i = int(port)
        start = time.perf_counter()
        with socket.create_connection((host, port_i), timeout=DEFAULT_TIMEOUT_SECONDS):
            status.latency_ms = (time.perf_counter() - start) * 1000.0
            status.reachable = True
    except ValueError:
        status.reason = f"non-integer port: {port!r}"
    except (ConnectionError, OSError) as e:
        status.reason = f"{type(e).__name__}: {e}"
    return status


def check_endpoints(routes: dict) -> list[EndpointStatus]:
    statuses: list[EndpointStatus] = []
    profiles = (routes or {}).get("profiles", {})
    for route_profile, cfg in profiles.items():
        if isinstance(cfg, dict):
            target = cfg.get("endpoint") or cfg.get("endpoint_ref", "")
        elif isinstance(cfg, str):
            # compact form: route_profile -> "profile@host:port"
            target = cfg
        else:
            continue
        if not target:
            continue
        statuses.append(check_endpoint(route_profile, target))
    return statuses


# --- DB delivery-failure counting -----------------------------------------


def load_db(path: str) -> sqlite3.Connection:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"coordination DB not found: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def count_stuck_deliveries(conn: sqlite3.Connection) -> list[DeliveryFailure]:
    """Count coordination_run rows whose delivery states never succeeded."""
    cols = ", ".join(FAILURE_COLUMNS)
    try:
        cur = conn.execute(
            f"SELECT run_id, target_profile, last_updated, "
            f"{cols} FROM coordination_run"
        )
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        # Table not yet created (fresh coordinator) -> nothing stuck.
        return []
    out: list[DeliveryFailure] = []
    for r in rows:
        stuck: list[str] = []
        last_updated = r["last_updated"]
        for col in FAILURE_COLUMNS:
            val = r[col]
            if val is None or str(val).strip().lower() in SUCCESS_STATES:
                continue
            stuck.append(f"{col}={val}")
        if stuck:
            out.append(
                DeliveryFailure(
                    run_id=r["run_id"],
                    target_profile=r["target_profile"],
                    stuck_columns=tuple(stuck),
                    last_updated=last_updated,
                )
            )
    return out


# --- formatting / exit codes ----------------------------------------------


def _seconds_ago(ts: float | None) -> str:
    if not ts:
        return "?"
    return f"{int(time.time() - ts)}s ago"


def print_report(report: HealthReport, warn_seconds: int, fail_seconds: int) -> None:
    print(f"direct-agent-api coordinator health check  {_seconds_ago(report.generated_at_ts)}")
    print(f"  host: {report.hostname}   db: {report.db_path}")
    print(f"  routes: {report.routes_path}")
    print()
    print(f"Endpoints: {sum(e.reachable for e in report.endpoints)}/{len(report.endpoints)} reachable")
    for e in report.endpoints:
        if e.reachable:
            print(f"  [OK]   {e.route_profile:<20} -> {e.target:<32} {e.latency_ms:.1f}ms")
        else:
            print(f"  [DOWN] {e.route_profile:<20} -> {e.target:<32} {e.reason}")
    print()
    stuck_now = sum(1 for d in report.stuck_deliveries if _is_stuck(d, fail_seconds))
    stuck_warn = len(report.stuck_deliveries)
    print(f"Stuck deliveries: {stuck_now} (threshold {fail_seconds}s) / {stuck_warn} total")
    for d in report.stuck_deliveries:
        since = _seconds_ago(d.last_updated)
        print(f"  ! run {d.run_id:<30} {d.target_profile:<14} stuck: {d.stuck_columns[0]} ...  ({since})")


def _is_stuck(d: DeliveryFailure, fail_seconds: int) -> bool:
    return d.last_updated is not None and (time.time() - d.last_updated) >= fail_seconds


def main() -> int:
    ap = argparse.ArgumentParser(description="direct-agent-api coordinator health check")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    ap.add_argument("--db", default=DEFAULT_DB_PATH, help="coordination DB path")
    ap.add_argument("--routes", help="override routes.json path")
    ap.add_argument("--fail-on-unreachable", action="store_true",
                    help="exit non-zero when an endpoint is unreachable")
    ap.add_argument("--warn-seconds", type=int, default=30,
                    help="stuck-delivery window to warn (default 30)")
    ap.add_argument("--fail-seconds", type=int, default=120,
                    help="stuck-delivery window to fail (default 120)")
    args = ap.parse_args()

    report = HealthReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        hostname=os.uname().nodename if hasattr(os, "uname") else "",
        db_path=args.db,
        routes_path="",
    )
    report.generated_at_ts = time.time()

    # routes
    routes_path = args.routes or find_routes_path()
    if not routes_path:
        print("ERROR: no direct-agent-api-routes.json found", file=sys.stderr)
        return 4
    report.routes_path = routes_path
    try:
        routes = load_routes(routes_path)
        report.endpoints = check_endpoints(routes)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read routes ({routes_path}): {e}", file=sys.stderr)
        return 4

    # DB delivery failures
    try:
        conn = load_db(args.db)
        report.stuck_deliveries = count_stuck_deliveries(conn)
    except FileNotFoundError as e:
        print(f"WARN: {e}", file=sys.stderr)
    except (sqlite3.Error, OSError) as e:
        print(f"ERROR: cannot read coordination DB: {e}", file=sys.stderr)
        return 4

    if args.json:
        print(json.dumps(report.__dict__, default=_json_default, indent=2))
        rc = 2 if report.total_unreachable else 0
        rc = rc or (3 if report.total_stuck else 0)
        return rc

    print_report(report, args.warn_seconds, args.fail_seconds)
    rc = 0
    if args.fail_on_unreachable and report.total_unreachable:
        rc = 2
    if report.total_stuck:
        rc = 3
    return rc


def _json_default(o: object) -> object:
    if isinstance(o, tuple):
        return list(o)
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


if __name__ == "__main__":
    sys.exit(main())
