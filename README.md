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

The approved Jarvis/136 hierarchy, caller allowlists, persistent forward/return tunnels, response obligation, and topology change-control gates are defined in [`ROUTING-TOPOLOGY.md`](ROUTING-TOPOLOGY.md).

Runtime endpoints and bearer keys remain external in `~/.hermes/direct-agent-api-routes.json`; no secrets live in this repository.

## Config (external, not committed)

Endpoints and bearer keys are read from `~/.hermes/direct-agent-api-routes.json`
via `_jarvis_route()`. No secrets live in this repo.

## Reconcile loop

`reconciler.py` runs `_reconcile_once()` every `RECONCILE_INTERVAL_SECONDS`
inside the coordinator profile.

## Tests

`tests/` covers team-approval gating and development-execution admission.
