# RWTS ACME DNS — Apache Platform Reference

**Purpose:** Loaded on demand when the user is configuring Apache with ACME DNS wildcard certificates via certbot.

---

## Prerequisites

- Apache with `mod_ssl` enabled
- `certbot` installed (via system package manager or pip)
- `certbot-dns-acmedns` plugin: `pip install certbot-dns-acmedns`
- acmedns registration credentials for the domain (from `/api/register`)
- CNAME record added in your DNS zone (see dns-setup reference)

---

## Enable mod_ssl

On Debian/Ubuntu:

```bash
a2enmod ssl
systemctl restart apache2
```

On RHEL/CentOS, `mod_ssl` is typically installed via:

```bash
dnf install mod_ssl
systemctl restart httpd
```

---

## Certbot Credential Files

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

**Important:** `dns_acmedns_api_url` must be `https://acmedns.realworld.net.au` — the root path, **not** `/api/`. The plugin communicates with the native acme-dns `/update` endpoint, which is routed at the root level.

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

Set permissions:

```bash
chmod 600 /etc/letsencrypt/acmedns/acmedns-registration.json
```

Replace the template variables with values from `/api/register`:

| Template variable | Source |
|---|---|
| `{{DOMAIN}}` | The domain you are certifying (e.g. `example.com`) |
| `{{USERNAME}}` | `username` from registration response |
| `{{PASSWORD}}` | `password` from registration response |
| `{{FULLDOMAIN}}` | `fulldomain` from registration response |
| `{{SUBDOMAIN}}` | `subdomain` from registration response |

For wildcard domains registered as `*.{{DOMAIN}}`, use the base domain (without `*.`) as the key, because the CNAME is set on `_acme-challenge.{{DOMAIN}}`.

---

## DNS Prerequisite

Before issuing a certificate, the CNAME record must be in place in your public DNS:

```
_acme-challenge.{{DOMAIN}}  CNAME  {{FULLDOMAIN}}
```

Allow time for DNS propagation before running certbot.

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

Certificates are stored under `/etc/letsencrypt/live/{{DOMAIN}}/`.

---

## Apache VirtualHost Configuration

### Debian/Ubuntu

Write the VirtualHost config to `/etc/apache2/sites-available/{{DOMAIN}}.conf`:

```apache
<VirtualHost *:443>
    ServerName {{DOMAIN}}
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/{{DOMAIN}}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/{{DOMAIN}}/privkey.pem
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
    DocumentRoot /var/www/html
</VirtualHost>

<VirtualHost *:80>
    ServerName {{DOMAIN}}
    Redirect permanent / https://{{DOMAIN}}/
</VirtualHost>
```

Then enable the site and reload:

```bash
a2ensite {{DOMAIN}}
apachectl configtest
systemctl reload apache2
```

### RHEL/CentOS

Write the VirtualHost config to `/etc/httpd/conf.d/{{DOMAIN}}.conf` using the same block above, then:

```bash
apachectl configtest
systemctl reload httpd
```

---

## Renewal

Certbot handles renewal automatically via a systemd timer or cron job installed at package time.

### Deploy hook

To reload Apache after each successful renewal, pass a deploy hook:

```bash
certbot renew --deploy-hook "systemctl reload apache2"
```

On RHEL/CentOS, replace `apache2` with `httpd`.

### Recommended cron job (if not using systemd timer)

```
0 0,12 * * * certbot renew --quiet --deploy-hook "systemctl reload apache2"
```

Runs twice daily. Certbot only renews certificates with fewer than 30 days remaining.

---

## Verification

### Test configuration syntax

```bash
apachectl configtest
```

Expected output: `Syntax OK`

### Reload Apache

```bash
systemctl reload apache2
```

### Inspect the live certificate

```bash
echo | openssl s_client -connect {{DOMAIN}}:443 -servername {{DOMAIN}} 2>/dev/null | openssl x509 -noout -dates
```

Expected output:

```
notBefore=Mar 24 00:00:00 2026 GMT
notAfter=Jun 22 23:59:59 2026 GMT
```

### List all certbot-managed certificates

```bash
certbot certificates
```

---

## Common Issues

| Problem | Likely cause |
|---|---|
| DNS challenge failed | CNAME record missing or not yet propagated |
| `certbot-dns-acmedns` plugin not found | Plugin not installed; run `pip install certbot-dns-acmedns` |
| `No module named certbot_dns_acmedns` | Plugin installed in wrong Python environment |
| Apache reports `SSLCertificateFile does not exist` | Certificate not yet issued; run certbot first |
| `AH00526: Syntax error` on reload | Run `apachectl configtest` to identify the offending line |
| API unreachable | Network issue or `dns_acmedns_api_url` misconfigured |
