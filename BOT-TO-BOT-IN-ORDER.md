# Bot-to-Bot in Order — the four servers

Goal: bot-to-bot communication across **ThinkCentre** (this machine),
**GX10**, **136**, and **46** must never get *silently* stuck.

This doc is the operator checklist. Pair it with `scripts/health_check.py`,
the automated proof that nothing gets stuck on a given server.

See `CONTRACT.md` for the read-only data-feed boundary between the actor
(`direct-agent-api`) and the observer (agent-intelligence). See
`ROUTING-TOPOLOGY.md` for the authoritative Jarvis/136 hierarchy, persistent
forward and return paths, caller allowlists, and response obligation.

---

## What already protects us (code layer)

Every coordinator→coordinator delivery on a server that runs the
`default` coordinator has these three self-healing nets:

| Net | How | Fixes |
|-----|-----|-------|
| **5s retry loop** | `_reconcile_once()` runs in a daemon thread every 5s | transient network/API drops |
| **DB-backed state** | `final_delivery_state`, `final_result_delivery_state` per run | no lost / duplicate deliveries |
| **Idempotency key** | `final-result-{run_id}` / `origin-return-{run_id}` on every POST | no double-wakeups |

A *transient* failure (brief network drop, server hiccup) **self-heals**.
What it **cannot** heal is a *wrong/stale endpoint* in `routes.json` — that
needs a config change, tunnel restart, or the health check to alert.

---

## The three gaps that still cause stuck comms

1. **Stale endpoints.** Cross-server entries use localhost-only endpoints behind
   supervised SSH tunnels. The Jarvis/136 development path currently uses
   `127.0.0.1:9677` on ThinkCentre for Jarvis → `cto136` and
   `127.0.0.1:19761` on 136 for `cto136` → Jarvis. If an endpoint goes stale
   or a tunnel dies, the POST fails and only a config/tunnel repair heals it.
   See `ROUTING-TOPOLOGY.md` for the authoritative hierarchy and forbidden
   lateral routes.
2. **Receiver-side reconciler must be alive.** The incoming `/v1/runs` handler
   just runs a profile — it does not create a `coordination_run`. A delivery to
   136/GX10/46 only "lands" if that server's `default` coordinator is also
   running and processing. Down reconciler → deliver into the void.
3. **Stuck delivery is silent.** There is no counter + alert. That is what the
   health check fixes (see below).

---

## The proof — `scripts/health_check.py`

Run it on **every** server (same discovery order as the plugin):

```bash
python3 scripts/health_check.py            # human-readable summary
python3 scripts/health_check.py --json     # machine-readable
```

- **Exit 0** — all endpoints reachable, no stuck deliveries.
- **Exit 2** — one or more endpoints unreachable (report the DOWN target).
- **Exit 3** — one or more stuck deliveries (report the run_id + target).
- **Exit 4** — config/DB error (bad JSON, unreadable DB).

It proves both halves of "cannot get stuck":
  - every endpoint in `routes.json` is reachable (TCP connect + latency), and
  - every `coordination_run` whose delivery state never succeeded is counted.

Schedule it (cron / systemd timer) on all four servers to make stuck
deliveries *visible* instead of silent.

---

## Per-server checklist (run on each of the four servers)

For **each** server — ThinkCentre, GX10, 136, 46:

- [ ] **`routes.json` endpoints are reachable** from this host.
      Run the health check; expect EXIT 0. Fix any DOWN target.
- [ ] **Endpoints are stable**, not stale LAN IPs. For cross-server entries,
      pin a reachable IP/FQDN or a managed tunnel — never a guessed address.
- [ ] **`default` coordinator is running** (reconciler thread starts only
      when the coordinator is the `default` profile — `tools.py`).
      Verify on every server; a delivery only lands if the receiver's
      coordinator is alive.
- [ ] **SSH tunnels have auto-restart** (systemd `Restart=on-failure`), so a
      dead tunnel (9671–9675 on ThinkCentre) wakes itself up.
- [ ] **Health check scheduled** (cron/systemd timer) so stuck deliveries
      alert instead of failing silently.

---

## Priority order

1. Add the health check to all four servers (the guarantee).
2. Fix `routes.json` cross-server endpoints to stable addresses.
3. Add systemd auto-restart for the SSH tunnels.
4. Alert wiring when a check reports EXIT 2 or 3 (feed the report to
   agent-intelligence, which already reads the coordination data).
