# Certbot — RWTS ACME DNS Platform Reference

**Purpose:** Loaded on demand when the user is configuring Certbot with the RWTS ACME DNS service.

---

## Prerequisites

- `certbot` installed (via system package manager or pip)
- `certbot-dns-acmedns` plugin: `pip install certbot-dns-acmedns`
- An acmedns registration for the domain (credentials from `/api/register`)

---

## Configuration Files

Both files belong in `/etc/letsencrypt/acmedns/`. Create the directory if it does not exist:

```bash
mkdir -p /etc/letsencrypt/acmedns
```

### acmedns.ini

```ini
dns_acmedns_api_url = https://acmedns.realworld.net.au
dns_acmedns_registration_file = /etc/letsencrypt/acmedns/acmedns-registration.json
```

Set permissions:

```bash
chmod 600 /etc/letsencrypt/acmedns/acmedns.ini
```

**Important:** `dns_acmedns_api_url` must be `https://acmedns.realworld.net.au` — the root path, **not** `/api/`. The plugin communicates directly with the native acme-dns `/update` endpoint, which is routed at the root level, not under `/api/`.

### acmedns-registration.json

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

Replace the template variables with the values returned by `/api/register`:

| Template variable | Source |
|---|---|
| `{{DOMAIN}}` | The domain you registered (e.g. `example.com`) |
| `{{USERNAME}}` | `username` from registration response |
| `{{PASSWORD}}` | `password` from registration response |
| `{{FULLDOMAIN}}` | `fulldomain` from registration response |
| `{{SUBDOMAIN}}` | `subdomain` from registration response |

Set permissions:

```bash
chmod 600 /etc/letsencrypt/acmedns/acmedns-registration.json
```

For wildcard domains registered as `*.{{DOMAIN}}`, the key in the JSON file should be the base domain without the `*.` prefix (i.e. `{{DOMAIN}}`), because the CNAME record is set on `_acme-challenge.{{DOMAIN}}`.

---

## DNS Prerequisite

Before issuing a certificate, the CNAME record must be in place on your public DNS:

```
_acme-challenge.{{DOMAIN}}  CNAME  {{FULLDOMAIN}}
```

Allow time for DNS propagation before proceeding.

---

## Issue Certificate

### Single domain

```bash
certbot certonly \
  --authenticator dns-acmedns \
  --dns-acmedns-credentials /etc/letsencrypt/acmedns/acmedns.ini \
  -d {{DOMAIN}}
```

### Wildcard + base domain

```bash
certbot certonly \
  --authenticator dns-acmedns \
  --dns-acmedns-credentials /etc/letsencrypt/acmedns/acmedns.ini \
  -d {{DOMAIN}} \
  -d '*.{{DOMAIN}}'
```

### Dry run (test without issuing)

```bash
certbot certonly \
  --authenticator dns-acmedns \
  --dns-acmedns-credentials /etc/letsencrypt/acmedns/acmedns.ini \
  -d {{DOMAIN}} \
  --dry-run
```

---

## Certificate Location

Issued certificates are stored under `/etc/letsencrypt/live/{{DOMAIN}}/`:

| File | Purpose |
|---|---|
| `fullchain.pem` | Certificate + intermediates (use this for most services) |
| `privkey.pem` | Private key |
| `cert.pem` | Certificate only |
| `chain.pem` | Intermediates only |

---

## Renewal

`certbot renew` handles renewal automatically. The acmedns plugin is invoked for each renewal using the stored credentials.

### Manual renewal trigger

```bash
certbot renew
```

### Recommended cron job

```
0 0,12 * * * certbot renew --quiet
```

This runs twice daily (midnight and noon). Let's Encrypt certificates expire after 90 days; certbot only renews when fewer than 30 days remain.

---

## Verification

### Test renewal without issuing

```bash
certbot renew --dry-run
```

### List all managed certificates

```bash
certbot certificates
```

### Inspect certificate dates and subject

```bash
openssl x509 -in /etc/letsencrypt/live/{{DOMAIN}}/fullchain.pem -noout -dates -subject
```
