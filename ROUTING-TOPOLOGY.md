# Direct-Agent Routing Topology

This document is the communication authority for the Jarvis/136 development hierarchy. Runtime endpoints and bearer keys remain external in `~/.hermes/direct-agent-api-routes.json`.

## Approved 136 hierarchy

```text
Jarvis ↔ cto136 ↔ developer136
                 ↔ qa136
```

Allowed directed routes:

| Caller | Allowed targets |
|---|---|
| Jarvis (`default`) | `cto136` within the 136 development hierarchy |
| `cto136` | `jarvis`, `developer136`, `qa136` |
| `developer136` (`coding`) | `cto136` only |
| `qa136` (`qa`) | `cto136` only |

Explicitly forbidden:

- `Jarvis ↔ developer136`
- `Jarvis ↔ qa136`
- `developer136 ↔ qa136`
- any additional lateral route inside this hierarchy

Other separately approved Jarvis specialist routes are outside this 136 hierarchy and are not changed by this contract.

## Response obligation

Every delegation remains owned by its caller. A delegation is terminal only when that exact caller receives either:

1. the correlated terminal result; or
2. an explicit correlated terminal error or timeout.

A transport-level connection, run ID, or accepted status alone is not a completed delegation. Intermediate children return to `cto136`; `cto136` returns to Jarvis. Return delivery must remain correlation-bound, idempotent, and loop-safe as described in `README.md`.

## Persistent transport

The approved transport shape is:

- Jarvis loopback forward `127.0.0.1:9677` to the `cto136` Direct Agent API on `127.0.0.1:9765`;
- loopback-only return forward `127.0.0.1:19761` on the 136 host to Jarvis on `127.0.0.1:9661`;
- `cto136`, `developer136`, and `qa136` communicate through host-local loopback endpoints;
- the `cto136` model endpoint is supplied through its independently supervised Ornith tunnel on `127.0.0.1:18006`.

SSH forwarding must remain least-privilege:

- loopback binds only;
- explicit `PermitOpen` destinations;
- explicit `PermitListen` return endpoint;
- no public listener;
- persistent services with automatic restart.

## Route allowlist requirements

The active caller entries in `direct-agent-api-routes.json` must enforce:

```text
default.allowed_targets = [cto136]       # only within this hierarchy
cto136.allowed_targets  = [jarvis, developer136, qa136]
coding.allowed_targets  = [cto136]
qa.allowed_targets      = [cto136]
```

Target-only route entries must not inherit unrelated caller allowlists. Backups and evidence are not active routing authority.

## Verification baseline — 2026-08-27

Verified at `2026-08-27T02:45:50Z`:

- Jarvis-to-CTO forward health: HTTP 200;
- CTO-to-Jarvis return health: HTTP 200;
- authenticated developer/QA-to-CTO route probe: accepted authentication (404 for an intentionally nonexistent run);
- correlated terminal acknowledgements for `Jarvis → cto136`, `cto136 → Jarvis`, `cto136 → developer136`, and `cto136 → qa136`;
- supervised Jarvis/CTO tunnel stable during the observation interval;
- supervised CTO/Ornith tunnel stable after clearing a stale SSH forwarding session.

Runtime evidence is deliberately not committed because it may contain operational metadata. The verification record remains in the controlled operations workspace under the evidence ID `agent-routing-tunnel-20260827T024550Z`.

## Change control

Any topology change requires:

1. an update to this document before or with the implementation;
2. least-privilege route allowlists on every caller;
3. forward and return transport tests;
4. one terminal correlated delegation test per changed edge;
5. confirmation that forbidden lateral routes remain absent;
6. an independently reviewable commit in this repository.
