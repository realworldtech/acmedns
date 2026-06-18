# HAProxy — RWTS ACME DNS Platform Reference

**Purpose:** Loaded on demand when the user is configuring HAProxy with the RWTS ACME DNS service. HAProxy does not handle ACME challenges natively — certificates are issued via certbot or acme.sh with a deploy hook that formats them for HAProxy.

---

## Prerequisites

- HAProxy 2.x or later installed
- certbot (with `certbot-dns-acmedns` plugin) **or** acme.sh installed
- An acmedns registration for each domain (credentials from `/api/register`):
  - `{{SUBDOMAIN}}` — UUID returned by `/api/register`
  - `{{USERNAME}}` — acme-dns account username
  - `{{PASSWORD}}` — acme-dns account password
  - `{{FULLDOMAIN}}` — `{{SUBDOMAIN}}.acmedns.realworld.net.au`
- CNAME record added in your DNS zone (see dns-setup reference)
- Certificate directory created and secured:
  ```bash
  mkdir -p /etc/haproxy/certs
  chmod 700 /etc/haproxy/certs
  ```

---

## How It Works

HAProxy reads TLS certificates from a directory or a single combined PEM file. The combined PEM must contain the full certificate chain followed by the private key — HAProxy does not accept them as separate files.

The workflow is:

1. certbot or acme.sh issues a certificate via the acme-dns DNS-01 challenge
2. A deploy hook (certbot) or `--reloadcmd` (acme.sh) concatenates the cert chain and private key into a single PEM file under `/etc/haproxy/certs/`
3. HAProxy is reloaded to pick up the new or renewed certificate

---

## Option A: certbot + Deploy Hook

### certbot credentials

Install the plugin and configure credentials (see the certbot platform reference for full details):

```bash
pip install certbot-dns-acmedns
mkdir -p /etc/letsencrypt/acmedns
```

`/etc/letsencrypt/acmedns/acmedns.ini`:
```ini
dns_acmedns_api_url = https://acmedns.realworld.net.au
dns_acmedns_registration_file = /etc/letsencrypt/acmedns/acmedns-registration.json
```

`/etc/letsencrypt/acmedns/acmedns-registration.json`:
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

Set permissions:
```bash
chmod 600 /etc/letsencrypt/acmedns/acmedns.ini
chmod 600 /etc/letsencrypt/acmedns/acmedns-registration.json
```

### Deploy hook

Create `/usr/local/bin/haproxy-deploy-cert.sh`:

```bash
#!/bin/bash
DOMAIN="${RENEWED_LINEAGE##*/}"
cat "${RENEWED_LINEAGE}/fullchain.pem" "${RENEWED_LINEAGE}/privkey.pem" \
  > "/etc/haproxy/certs/${DOMAIN}.pem"
chmod 600 "/etc/haproxy/certs/${DOMAIN}.pem"
systemctl reload haproxy
```

Make it executable:
```bash
chmod +x /usr/local/bin/haproxy-deploy-cert.sh
```

`RENEWED_LINEAGE` is set automatically by certbot to the path of the renewed certificate lineage (e.g. `/etc/letsencrypt/live/example.com`). The script extracts the domain name from the last path component.

### Issue certificate

```bash
certbot certonly \
  --authenticator dns-acmedns \
  --dns-acmedns-credentials /etc/letsencrypt/acmedns/acmedns.ini \
  -d {{DOMAIN}} \
  --deploy-hook '/usr/local/bin/haproxy-deploy-cert.sh'
```

For wildcard + base domain:

```bash
certbot certonly \
  --authenticator dns-acmedns \
  --dns-acmedns-credentials /etc/letsencrypt/acmedns/acmedns.ini \
  -d {{DOMAIN}} \
  -d '*.{{DOMAIN}}' \
  --deploy-hook '/usr/local/bin/haproxy-deploy-cert.sh'
```

The deploy hook runs automatically on every successful renewal.

---

## Option B: acme.sh

Configure acme.sh environment variables (saved to `~/.acme.sh/account.conf` after first use):

```bash
export ACMEDNS_UPDATE_URL="https://acmedns.realworld.net.au/update"
export ACMEDNS_USERNAME="{{USERNAME}}"
export ACMEDNS_PASSWORD="{{PASSWORD}}"
export ACMEDNS_SUBDOMAIN="{{SUBDOMAIN}}"
```

Issue the certificate:

```bash
acme.sh --issue --dns dns_acmedns -d {{DOMAIN}}
```

Install to HAProxy (creates the combined PEM and reloads HAProxy on every renewal):

```bash
acme.sh --install-cert -d {{DOMAIN}} \
  --fullchain-file /etc/haproxy/certs/{{DOMAIN}}.pem \
  --key-file /etc/haproxy/certs/{{DOMAIN}}.key \
  --reloadcmd "cat /etc/haproxy/certs/{{DOMAIN}}.pem /etc/haproxy/certs/{{DOMAIN}}.key \
    > /etc/haproxy/certs/{{DOMAIN}}-combined.pem \
    && chmod 600 /etc/haproxy/certs/{{DOMAIN}}-combined.pem \
    && systemctl reload haproxy"
```

Point HAProxy at `{{DOMAIN}}-combined.pem` (see HAProxy configuration below).

---

## HAProxy Configuration

Add TLS to the `haproxy.cfg` frontend. HAProxy loads all `.pem` files from a directory automatically when you specify a directory path in the `crt` directive.

```
frontend https
    bind *:443 ssl crt /etc/haproxy/certs/
    default_backend app

frontend http
    bind *:80
    redirect scheme https code 301

backend app
    server app1 127.0.0.1:8080 check
```

| Directive | Notes |
|---|---|
| `crt /etc/haproxy/certs/` | Directory — HAProxy loads all `.pem` files found here |
| `redirect scheme https code 301` | Redirects all HTTP traffic to HTTPS |
| `server app1 127.0.0.1:8080 check` | Upstream backend; adjust address and port to match your application |

For a single certificate file rather than a directory:

```
bind *:443 ssl crt /etc/haproxy/certs/{{DOMAIN}}.pem
```

---

## File Locations

| File | Location | Notes |
|---|---|---|
| HAProxy config | `/etc/haproxy/haproxy.cfg` | Add `frontend` and `backend` blocks here |
| Combined certificate PEM | `/etc/haproxy/certs/{{DOMAIN}}.pem` | `fullchain.pem` + `privkey.pem` concatenated |
| Certbot credentials | `/etc/letsencrypt/acmedns/` | Keep outside version control |
| Deploy hook | `/usr/local/bin/haproxy-deploy-cert.sh` | Must be executable |

---

## Renewal

**certbot:** The deploy hook is stored with the certificate lineage and runs automatically on every successful `certbot renew`. Add a cron job if one is not already present:

```
0 0,12 * * * certbot renew --quiet
```

**acme.sh:** Renewal is fully automatic via the cron job installed by acme.sh. The `--reloadcmd` registered with `--install-cert` runs automatically on each renewal.

---

## Verification

Validate HAProxy configuration before reloading:

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
```

Reload HAProxy:

```bash
systemctl reload haproxy
```

Inspect the certificate served on port 443:

```bash
echo | openssl s_client -connect {{DOMAIN}}:443 -servername {{DOMAIN}} 2>/dev/null \
  | openssl x509 -noout -dates -subject
```

Expected output (Let's Encrypt certificate):

```
notBefore=Mar 24 00:00:00 2026 GMT
notAfter=Jun 22 23:59:59 2026 GMT
subject=CN={{DOMAIN}}
```

---

## Common Issues

### HAProxy fails to start after cert update

- Ensure the combined PEM contains `fullchain.pem` first, then `privkey.pem` — reversing the order causes a parse error
- Confirm permissions: the file must be readable by the HAProxy process user (typically `root` or `haproxy`)
- Run `haproxy -c -f /etc/haproxy/haproxy.cfg` to identify config errors before reloading

### Deploy hook not running on renewal

- certbot only runs deploy hooks when a certificate is actually renewed (not on dry runs)
- Test the hook manually: `RENEWED_LINEAGE=/etc/letsencrypt/live/{{DOMAIN}} /usr/local/bin/haproxy-deploy-cert.sh`
- Confirm the hook is executable: `ls -l /usr/local/bin/haproxy-deploy-cert.sh`

### Certificate not being issued

- Confirm the CNAME record is resolving: `dig CNAME _acme-challenge.{{DOMAIN}}`
- Confirm acmedns credentials are correct and the registration file permissions are `600`
- Run with `--dry-run` (certbot) or `--staging` (acme.sh) to test without consuming rate limits

### HAProxy serving old certificate after renewal

- The deploy hook or `--reloadcmd` must call `systemctl reload haproxy` (not `restart`) — a reload is sufficient and avoids dropping existing connections
- Confirm the hook actually ran: check `journalctl -u certbot` or `~/.acme.sh/acme.sh.log`
