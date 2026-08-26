# Data-Feed Contract: `direct-agent-api` → Agent Intelligence System

**Purpose:** Decouples the actor (communication rules) from the observer (agent intelligence) so a witness on the 136 server can read agent communication without being coupled into the action path.

---

## 1. Responsibilities

| System | Role | Direction |
|---------|------|-----------|
| **`direct-agent-api`** (this repo) | Actor — decides what agents **may** do to each other (routing, delegation, `allowed_targets`, secret handling) | **writes** the coordination log |
| **Agent Intelligence System** (136 server) | Observer — monitors, analyzes, reports drift/quality of all agent communication | **reads** the coordination log (read-only) |

They connect at the **data layer only**. No code import between them.

---

## 2. Source of truth (data feed)

- **Table:** `coordination_run`
- **DB:** `~/.hermes/team-coordination.db`
- **Created dynamically at first run** (table may not exist until the first delegated run)

### Schema (authoritative)

```sql
CREATE TABLE coordination_run (
    run_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    calling_profile TEXT NOT NULL,   -- the delegating / calling agent
    target_profile TEXT NOT NULL,    -- the agent that did the work
    parent_session_id TEXT NOT NULL DEFAULT '',
    objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'started',
    resume_state TEXT NOT NULL DEFAULT 'active',
    final_delivery_state TEXT NOT NULL DEFAULT 'pending',
    final_output TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
```

### Access rules for the reader
- **Read-only** — never `UPDATE`, `DELETE`, `INSERT`, `DROP`, `CREATE`, or `VACUUM`.
- The observer must open the connection in `ro` / read-only mode where the SQLite layer supports it.
- New columns may be added forward (additive, backward-compatible). A reader that hits an unknown column must treat it as informational, not fail.

---

## 3. Data categories (governance)

| Field | Category | Notes |
|-------|----------|-------|
| run_id, trace_id | identifier | correlation key only |
| calling_profile, target_profile | actor label | identity of agents, not personal data |
| objective | content | the delegated task text |
| status, resume_state, final_delivery_state | lifecycle | operational state |
| final_output | **content** | may contain task output — treat per data-handling policy |
| created_at, updated_at | metadata | timestamps (UTC epoch) |

`final_output` is the only field that may carry task-derived content. Monitor it per the agent-intelligence data-handling policy: **derived outputs persist; raw chatter stays in bounded, audited jobs.**

---

## 4. Boundary guarantees

1. **Actor does not know the observer.** `direct-agent-api` writes the log; it does not call or notify the intelligence system.
2. **Observer does not control the actor.** The read-only reader never influences routing, delegation, or `allowed_targets`.
3. **Separation of duties.** A witness that reads the log cannot also author the rules → it can catch its own drift or bias.
4. **Failure isolation.** A monitoring crash cannot stall a delegated run (and vice versa) because they share a data feed, not a code path.
5. **No secret leakage.** The log carries profile labels and objective text only. No API keys, bearer tokens, or credentials are written here (keys resolve from external config only).

---

## 5. Contract change process

- Actor changes that alter schema or log contents → update this doc before merging.
- Observer changes that change how the feed is consumed → keep read-only contract enforced.
- Both repos remain independent; coordinate via this file, not via cross-repo imports.

---

_Last updated: 2026-08-26 — initial contract definition._
