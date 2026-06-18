# acme.sh — RWTS ACME DNS Platform Reference

**Purpose:** Loaded on demand when the user is issuing certificates with acme.sh against the RWTS ACME DNS service.

---

## Prerequisites

- acme.sh installed:
  ```bash
  curl https://get.acme.sh | sh -s email=you@example.com
  ```
- ACME DNS registration credentials from the RWTS registration service (subdomain, username, password). Obtain these via `POST /api/register` or the admin UI.

---

## Configuration

Set environment variables before running acme.sh. These are saved automatically to `~/.acme.sh/account.conf` after first use and do not need to be re-exported on subsequent runs.

```bash
export ACMEDNS_UPDATE_URL="https://acmedns.realworld.net.au/update"
export ACMEDNS_USERNAME="{{USERNAME}}"
export ACMEDNS_PASSWORD="{{PASSWORD}}"
export ACMEDNS_SUBDOMAIN="{{SUBDOMAIN}}"
```

Replace `{{USERNAME}}`, `{{PASSWORD}}`, and `{{SUBDOMAIN}}` with the values returned by the registration endpoint.

> **Important:** `ACMEDNS_UPDATE_URL` must point to `https://acmedns.realworld.net.au/update` (the root `/update` path). Do **not** use `/api/update` — that path does not exist.

> **Note:** Verify these environment variable names against the current acme.sh DNS API docs at `https://github.com/acmesh-official/acme.sh/wiki/dnsapi` — variable names may change between versions.

---

## Issue Certificate

**Single domain:**
```bash
acme.sh --issue --dns dns_acmedns -d {{DOMAIN}}
```

**Domain with wildcard (both bare and wildcard in one certificate):**
```bash
acme.sh --issue --dns dns_acmedns -d {{DOMAIN}} -d '*.{{DOMAIN}}'
```

**Dry run (staging — does not issue a real certificate):**
```bash
acme.sh --issue --dns dns_acmedns -d {{DOMAIN}} --staging
```

---

## Certificate Locations

After issue, certificates are stored in:

```
~/.acme.sh/{{DOMAIN}}/
```

| File | Contents |
|---|---|
| `{{DOMAIN}}.cer` | Domain certificate |
| `{{DOMAIN}}.key` | Private key |
| `ca.cer` | Intermediate CA certificate |
| `fullchain.cer` | Full chain (domain cert + CA) |

---

## Install Certificate to Web Server

Use `--install-cert` to copy certificates to the appropriate location and reload the web server. Do not reference the `~/.acme.sh/` files directly in production.

**Nginx:**
```bash
acme.sh --install-cert -d {{DOMAIN}} \
  --key-file /etc/nginx/ssl/{{DOMAIN}}.key \
  --fullchain-file /etc/nginx/ssl/{{DOMAIN}}.pem \
  --reloadcmd "systemctl reload nginx"
```

**Apache:**
```bash
acme.sh --install-cert -d {{DOMAIN}} \
  --key-file /etc/apache2/ssl/{{DOMAIN}}.key \
  --fullchain-file /etc/apache2/ssl/{{DOMAIN}}.pem \
  --reloadcmd "systemctl reload apache2"
```

The `--reloadcmd` is run automatically on every renewal.

---

## Renewal

Renewal is fully automatic. acme.sh installs a cron job during installation that runs daily. Certificates are renewed approximately 30 days before expiry. No manual action is required.

---

## Verification

**List all managed certificates:**
```bash
acme.sh --list
```

**Force a manual renewal (for testing):**
```bash
acme.sh --renew -d {{DOMAIN}} --force
```

**Show certificate details:**
```bash
acme.sh --info -d {{DOMAIN}}
```
