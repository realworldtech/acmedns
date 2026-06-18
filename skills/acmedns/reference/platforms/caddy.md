# Caddy — RWTS ACME DNS Platform Reference

**Purpose:** Loaded on demand when the user is configuring Caddy with the RWTS ACME DNS service for automatic TLS.

---

## Prerequisites

- Caddy with the `caddy-dns/acmedns` DNS module — requires a custom build (not included in the standard Caddy binary)
- `xcaddy` build tool
- acmedns registration credentials (username, password, fulldomain, subdomain) — obtain via `POST /api/register` or the admin UI
- CNAME record added in your DNS zone (see dns-setup reference)

> **Module availability note:** The `caddy-dns/acmedns` module may not always be actively maintained. Before building, check the [caddy-dns GitHub org](https://github.com/caddy-dns) for current status and the latest module path. If the module is unavailable or stale, use the [LEGO fallback](#fallback-lego-acme-dns-provider) described at the bottom of this file.

---

## Build Caddy with the acmedns DNS Module

Install `xcaddy` and build a custom Caddy binary:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/caddy-dns/acmedns
```

This produces a `caddy` binary in the current directory. Replace the system binary or install it:

```bash
sudo mv caddy /usr/bin/caddy
sudo setcap cap_net_bind_service=+ep /usr/bin/caddy
```

Verify the module is present:

```bash
caddy list-modules | grep acmedns
```

---

## Configuration Files

### Caddyfile

Place the Caddyfile at `/etc/caddy/Caddyfile`.

**Single domain:**

```
{{DOMAIN}} {
    tls {
        dns acmedns {
            server_url https://acmedns.realworld.net.au
            registration /etc/caddy/acmedns-registration.json
        }
    }
    reverse_proxy localhost:8080
}
```

**Wildcard domain (covers `*.{{DOMAIN}}`):**

```
*.{{DOMAIN}} {
    tls {
        dns acmedns {
            server_url https://acmedns.realworld.net.au
            registration /etc/caddy/acmedns-registration.json
        }
    }
    @match host {args[0]}.{{DOMAIN}}
    handle @match {
        reverse_proxy localhost:8080
    }
}
```

**Wildcard plus base domain (both in one block):**

```
{{DOMAIN}} *.{{DOMAIN}} {
    tls {
        dns acmedns {
            server_url https://acmedns.realworld.net.au
            registration /etc/caddy/acmedns-registration.json
        }
    }
    reverse_proxy localhost:8080
}
```

> **Important:** `server_url` must be `https://acmedns.realworld.net.au` — the root path, **not** `/api/`. The module communicates with the native acme-dns `/update` endpoint routed at the root level.

---

### acmedns-registration.json

Place this file at the path referenced in `registration` (e.g. `/etc/caddy/acmedns-registration.json`).

**Single domain:**

```json
{
  "{{DOMAIN}}": {
    "username": "{{USERNAME}}",
    "password": "{{PASSWORD}}",
    "fulldomain": "{{FULLDOMAIN}}",
    "subdomain": "{{SUBDOMAIN}}",
    "allowfrom": []
  }
}
```

**Wildcard plus base domain (separate registrations):**

```json
{
  "{{DOMAIN}}": {
    "username": "{{USERNAME_BASE}}",
    "password": "{{PASSWORD_BASE}}",
    "fulldomain": "{{FULLDOMAIN_BASE}}",
    "subdomain": "{{SUBDOMAIN_BASE}}",
    "allowfrom": []
  },
  "*.{{DOMAIN}}": {
    "username": "{{USERNAME_WILDCARD}}",
    "password": "{{PASSWORD_WILDCARD}}",
    "fulldomain": "{{FULLDOMAIN_WILDCARD}}",
    "subdomain": "{{SUBDOMAIN_WILDCARD}}",
    "allowfrom": []
  }
}
```

Replace template variables with values returned by `/api/register`:

| Variable | Description | Example |
|---|---|---|
| `{{DOMAIN}}` | The domain being certified | `example.com` |
| `{{USERNAME}}` | acmedns account username (UUID) | `a1b2c3d4-...` |
| `{{PASSWORD}}` | acmedns account password | `...` |
| `{{FULLDOMAIN}}` | Full CNAME target from registration | `a1b2c3d4-....acmedns.realworld.net.au` |
| `{{SUBDOMAIN}}` | Subdomain component of fulldomain | `a1b2c3d4-...` |

Set strict permissions on the file — it contains credentials:

```bash
chmod 600 /etc/caddy/acmedns-registration.json
chown caddy:caddy /etc/caddy/acmedns-registration.json
```

Do not commit this file to version control.

---

## Where to Put Each File

| File | Location | Notes |
|---|---|---|
| `Caddyfile` | `/etc/caddy/Caddyfile` | Main Caddy configuration |
| `acmedns-registration.json` | Path set in `registration` directive | Readable by Caddy process; `chmod 600` |

---

## DNS Prerequisite

Before Caddy can issue a certificate, the CNAME record must be in place on your public DNS:

```
_acme-challenge.{{DOMAIN}}  CNAME  {{FULLDOMAIN}}
```

Allow time for DNS propagation before starting Caddy or reloading the config.

---

## Renewal

Renewal is fully automatic. Caddy monitors certificate expiry and renews certificates internally before they expire. No cron job, systemd timer, or manual intervention is required.

---

## Verification

Validate the Caddyfile syntax before reloading:

```bash
caddy validate --config /etc/caddy/Caddyfile
```

Confirm the issued certificate subject after Caddy has started:

```bash
curl -v https://{{DOMAIN}} 2>&1 | grep "subject:"
```

Inspect certificate dates and subject directly:

```bash
echo | openssl s_client -connect {{DOMAIN}}:443 -servername {{DOMAIN}} 2>/dev/null | openssl x509 -noout -dates -subject
```

Check Caddy logs for ACME activity:

```bash
journalctl -u caddy -f | grep -i "acme\|certificate\|tls"
```

---

## Common Issues

| Problem | Likely cause |
|---|---|
| `unknown module: dns.providers.acmedns` | Custom build was not done with `xcaddy`, or build used wrong module path |
| DNS challenge failed | CNAME record missing, not yet propagated, or `server_url` is wrong |
| `registration` file not readable | File permissions or path mismatch between Caddyfile and actual file location |
| Certificate issued for wrong domain | Key in `acmedns-registration.json` does not match the domain Caddy is requesting |
| `server_url` 404 errors | URL contains `/api/` suffix — use root path only |

---

## Fallback: LEGO acme-dns Provider

If the `caddy-dns/acmedns` module is unavailable or unmaintained, Caddy can delegate DNS challenges to an external ACME solver using the [LEGO](https://go-acme.github.io/lego/) client. This approach uses an external process to handle the DNS-01 challenge and writes the certificate to disk, which Caddy can then reference.

### Install LEGO

```bash
# Download the latest release from https://github.com/go-acme/lego/releases
# Example for Linux amd64:
curl -LO https://github.com/go-acme/lego/releases/latest/download/lego_linux_amd64.tar.gz
tar xzf lego_linux_amd64.tar.gz
sudo mv lego /usr/local/bin/lego
```

### Issue certificate with LEGO using acme-dns provider

```bash
export ACME_DNS_API_BASE="https://acmedns.realworld.net.au"
export ACME_DNS_STORAGE_PATH="/etc/caddy/acmedns-registration.json"

lego \
  --email you@example.com \
  --dns acme-dns \
  --domains {{DOMAIN}} \
  --domains '*.{{DOMAIN}}' \
  --path /etc/lego \
  run
```

### Reference the certificate in Caddyfile

```
{{DOMAIN}} *.{{DOMAIN}} {
    tls /etc/lego/certificates/{{DOMAIN}}.crt /etc/lego/certificates/{{DOMAIN}}.key
    reverse_proxy localhost:8080
}
```

### Renewal with LEGO

Replace `run` with `renew` in the LEGO command and add a cron job:

```
0 0,12 * * * ACME_DNS_API_BASE=https://acmedns.realworld.net.au ACME_DNS_STORAGE_PATH=/etc/caddy/acmedns-registration.json lego --email you@example.com --dns acme-dns --domains {{DOMAIN}} --domains '*.{{DOMAIN}}' --path /etc/lego renew --renew-hook "systemctl reload caddy"
```

The `--renew-hook` reloads Caddy after each successful renewal so it picks up the new certificate.
