# Set up the `cto136` gateway in Hermes Desktop

This guide documents how to connect Hermes Desktop on this Mac to the existing `cto136` profile on the **main-staging** host.

## Verified deployment

| Item | Value |
|---|---|
| Host | `main-staging` |
| Tailscale IP | `100.80.254.84` |
| Desktop gateway name | `cto staging main` |
| Remote gateway URL | `http://100.80.254.84:9120` |
| Hermes profile | `cto136` |
| Profile directory | `/home/cto136/.hermes/profiles/cto136` |
| Linux service account | `cto136` |
| Desktop backend service | `hermes-cto136-desktop.service` |
| Existing messaging/agent service | `hermes-cto136.service` |
| Existing agent gateway listener | `127.0.0.1:9765` |
| Authentication configuration | `/etc/cto136/dashboard.env` |

> The listener on `127.0.0.1:9765` belongs to the existing messaging/agent gateway. Hermes Desktop uses the separate authenticated backend at `100.80.254.84:9120`.

## Prerequisites

1. The Mac must be connected to the Tailscale network containing `main-staging`.
2. `tailscale ping 100.80.254.84` must succeed.
3. The operator must have SSH access to the host for diagnostics.
4. `hermes-cto136.service` and `hermes-cto136-desktop.service` should be running.
5. The dashboard username and password must be available to the person adding the gateway.

## 1. Check network access from the Mac

```bash
tailscale ping 100.80.254.84
```

Check that the Desktop backend answers:

```bash
curl --fail --silent --show-error \
  http://100.80.254.84:9120/api/status
```

Expected properties in the response include:

```json
{
  "auth_required": true,
  "auth_providers": ["basic"],
  "overall": "ok"
}
```

The response should also include the `cto136` profile.

## 2. Get the dashboard username from the host

The agent gateway username must be read from:

```text
/etc/cto136/dashboard.env
```

Use the following command on `main-staging`. It prints only the username and avoids displaying the password hash or signing secret:

```bash
sudo sh -c '
while IFS="=" read -r key value; do
  if [ "$key" = "HERMES_DASHBOARD_BASIC_AUTH_USERNAME" ]; then
    printf "%s\n" "$value"
  fi
done < /etc/cto136/dashboard.env
'
```

In the verified setup, the username is:

```text
cto136
```

### Do not expose the other values

`/etc/cto136/dashboard.env` may also contain sensitive values such as:

- `HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH`
- `HERMES_DASHBOARD_BASIC_AUTH_SECRET`

Do not copy these values into tickets, chat messages, documentation, or source control. The password hash is not the login password.

On this Mac, the corresponding login password is stored in the macOS login Keychain under the item:

```text
Hermes main-staging cto136
```

Use Keychain Access to retrieve it when signing in. Do not place the plaintext password in this document.

## 3. Add the Remote gateway in Hermes Desktop

1. Open **Hermes Desktop**.
2. Open **Settings**.
3. Select **Gateways**.
4. Choose **Remote gateway**.
5. Enter:

   | Field | Value |
   |---|---|
   | Name | `cto staging main` |
   | Gateway URL | `http://100.80.254.84:9120` |

6. Test or save the connection.
7. If Hermes reports that authentication is required, edit the saved gateway and click **Sign in**.
8. Enter the username obtained from `/etc/cto136/dashboard.env` and the corresponding password.
9. Complete the sign-in flow.
10. In the profile rail, select **`cto136`** under **`cto staging main`**.

## 4. Verify the profile and skills

Open **Capabilities** in Hermes Desktop.

The profile selector should display:

```text
cto136 — cto staging main (current)
```

A successful connection should show:

- Gateway status: **Ready**
- The `cto136` skills list
- The `cto136` tools list
- No authentication or unavailable warning

At the time this guide was created, the verified remote profile loaded:

- **78 skills**
- **24 tools**

These counts may change as skills and tools are installed or updated. Treat a successfully populated list—not a specific count—as the acceptance criterion.

## Recovery when `cto staging main` is down

### A. Confirm Tailscale reachability

From the Mac:

```bash
tailscale ping 100.80.254.84
```

If this fails, repair Tailscale membership, sharing, routing, or ACL access before troubleshooting Hermes.

### B. Check both server services

On `main-staging`:

```bash
sudo systemctl status hermes-cto136.service
sudo systemctl status hermes-cto136-desktop.service
```

The two services have different purposes:

- `hermes-cto136.service` runs the existing `cto136` agent/messaging gateway.
- `hermes-cto136-desktop.service` exposes the authenticated Hermes Desktop backend on port `9120`.

### C. Check listeners

```bash
sudo ss -lntp
```

Expected listeners include:

```text
100.80.254.84:9120   # Hermes Desktop backend
127.0.0.1:9765       # Existing cto136 agent gateway
```

### D. Restart only the failed Desktop service

If the Desktop backend is stopped or unhealthy:

```bash
sudo systemctl restart hermes-cto136-desktop.service
sudo systemctl status hermes-cto136-desktop.service
```

Do not restart `hermes-cto136.service` unless the existing agent/messaging gateway is also unhealthy.

### E. Review recent logs

```bash
sudo journalctl \
  --unit hermes-cto136-desktop.service \
  --lines 100 \
  --no-pager
```

A healthy startup includes messages similar to:

```text
HERMES_BACKEND_READY port=9120
Hermes backend listening on 100.80.254.84:9120
```

### F. Verify authentication is enabled

```bash
curl --fail --silent --show-error \
  http://100.80.254.84:9120/api/status
```

Confirm:

- `auth_required` is `true`
- `auth_providers` includes `basic`
- `overall` is `ok`

If the service is reachable but Hermes Desktop displays **Unavailable**, edit the connection and sign in again. An HTTP status check can pass while the authenticated Desktop session or WebSocket connection still requires reauthentication.

## Security notes

- Port `9120` is bound to the server's Tailscale IP and is intended for private Tailscale access.
- Do not expose `9120` directly to the public internet.
- The URL uses HTTP because traffic is carried over the private Tailscale network. Use HTTPS and an authenticated reverse proxy or zero-trust access layer if the gateway must be reachable outside Tailscale.
- Never disable Hermes authentication on a non-loopback bind.
- Never publish `/etc/cto136/dashboard.env`.
- Keep the generated login password in an approved password manager or macOS Keychain.
- Keep command approvals enabled for an agent reachable remotely.

## Relevant server files

```text
/etc/cto136/dashboard.env
/etc/systemd/system/hermes-cto136-desktop.service
/etc/systemd/system/hermes-cto136.service
/home/cto136/.hermes/profiles/cto136
```

## Quick verification checklist

- [ ] Tailscale ping to `100.80.254.84` succeeds.
- [ ] `hermes-cto136.service` is active.
- [ ] `hermes-cto136-desktop.service` is active.
- [ ] `http://100.80.254.84:9120/api/status` returns `overall: ok`.
- [ ] Authentication is required and the `basic` provider is listed.
- [ ] Desktop contains a Remote gateway named `cto staging main`.
- [ ] The signed-in profile is `cto136`.
- [ ] Capabilities shows a populated Skills list.
- [ ] Desktop footer reports **Gateway ready**.
