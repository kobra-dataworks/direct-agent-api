# Direct Agent API — Coordinator Return Delivery

Hermes plugin that extends the `direct-agent-api` control plane so the
**coordinating** agent (`default`) notifies the **calling** (delegating) agent
when a delegated run completes. This closes loop element 9: the agent who
delegates an task is informed at its conclusion.

## What changed

- `_deliver_return_to_caller(row, status, output, now)` in `tools.py`: mirrors
  `_deliver_final_result` and POSTs the `final_output` back to the delegating
  profile's endpoint `{endpoint}/v1/runs`.
- Wired into the `_reconcile_once()` loop: called after
  `_deliver_final_result()` on every terminal run (`completed` / `failed` /
  `cancelled`).
- `counters["origin_returns_delivered"]` added to the reconcile counters dict.

## Loop safety

- Never delivered back to `default` (the coordinator) — guard:
  `row["calling_profile"] != "default"`.
- Idempotent: writes `final_return_delivery_state = 'delivered'` and only
  posts once per completed run.
- The reconciler only processes coordinator-owned `coordination_run` records;
  an incoming `/v1/runs` POST creates a generic run (no new
  `coordination_run`), so the return loop is self-terminating.

## Routing authority

The approved Jarvis/136 hierarchy, the isolated Jarvis/host46 coordinator edge,
caller allowlists, persistent forward/return tunnels, response obligation, and
topology change-control gates are defined in
[`ROUTING-TOPOLOGY.md`](ROUTING-TOPOLOGY.md).

Runtime endpoints and bearer keys remain external in `~/.hermes/direct-agent-api-routes.json`; no secrets live in this repository.

## Config (external, not committed)

Endpoints and authentication metadata are read from `~/.hermes/direct-agent-api-routes.json`.
Secrets are referenced by environment variable name (for example
`secret_env`) or by the transitional legacy bearer field; no secret values live
in this repo.

## Directional request authentication

PR2 adds explicit `direct-agent-hmac-v1` request authentication for direct
agent API calls. The signer computes HMAC-SHA256 over this canonical message:

```text
METHOD
/path?query
unix_timestamp_seconds
nonce
sha256(body_bytes)
caller->target
direct-agent-hmac-v1
```

The transport sends `X-Direct-Agent-Protocol`, `X-Direct-Agent-Key-Id`,
`X-Direct-Agent-Timestamp`, `X-Direct-Agent-Nonce`,
`X-Direct-Agent-Body-SHA256`, `X-Direct-Agent-Direction`,
`X-Direct-Agent-Signature`, and `X-Direct-Agent-Auth-Mode` headers. Receiver
verification uses constant-time digest/signature comparison, rejects timestamps
outside ±60 seconds, enforces per-key nonce replay rejection with a bounded
cache, and accepts only the configured current/next key IDs for rotation.

Routes may use `auth.mode = "dual"` during transition to send both legacy
Bearer and HMAC headers, then move to `auth.mode = "hmac"` after every receiver
has been upgraded. `auth.mode = "bearer"` preserves legacy behavior for routes
that have not been migrated yet.

## Reconcile loop

`reconciler.py` runs `_reconcile_once()` every `RECONCILE_INTERVAL_SECONDS`
inside the coordinator profile.

## Tests

`tests/` covers team-approval gating and development-execution admission.
