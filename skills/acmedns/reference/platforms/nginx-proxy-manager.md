# RWTS ACME DNS — Nginx Proxy Manager Platform Reference

**Purpose:** Loaded on demand when the user is configuring ACME DNS wildcard certificates with Nginx Proxy Manager (NPM).

---

## Prerequisites

- Nginx Proxy Manager installed and running
- Admin access to NPM web interface
- acmedns registration credentials (username, password, fulldomain, subdomain) — obtain these by registering a domain via the RWTS ACME DNS registration API

---

## Configuration — via NPM web interface

1. Navigate to **SSL Certificates** → **Add SSL Certificate** → **Let's Encrypt**
2. Enter domain(s): `{{DOMAIN}}` (and `*.{{DOMAIN}}` for wildcard)
3. Enable **"Use a DNS Challenge"**
4. Select DNS Provider: **Acme-DNS** (if available) or use **Custom**
5. If using Custom, set the Credentials File Content to:

```ini
dns_acmedns_api_url = https://acmedns.realworld.net.au
dns_acmedns_registration_file = /data/acmedns-registration.json
```

6. Upload or create the registration JSON file in the NPM data directory (see below)

---

## Configuration — acmedns-registration.json

Create a file with the following structure, using the credentials from your acmedns registration:

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

**Template variable reference:**

| Variable | Description | Example |
|---|---|---|
| `{{DOMAIN}}` | The domain being certified | `example.com` |
| `{{USERNAME}}` | acmedns account username (UUID) | `a1b2c3d4-...` |
| `{{PASSWORD}}` | acmedns account password | `...` |
| `{{FULLDOMAIN}}` | Full CNAME target provided at registration | `a1b2c3d4-....acmedns.realworld.net.au` |
| `{{SUBDOMAIN}}` | Subdomain component of fulldomain | `a1b2c3d4-...` |

**Placement:** The file must be accessible at `/data/acmedns-registration.json` inside the NPM container.

If running NPM via Docker, mount the file into the container:

```yaml
volumes:
  - ./acmedns-registration.json:/data/acmedns-registration.json:ro
```

---

## DNS CNAME Setup

Before requesting the certificate, create the required CNAME record in your DNS provider:

```
_acme-challenge.{{DOMAIN}}  CNAME  {{FULLDOMAIN}}
```

For wildcard certificates covering both `{{DOMAIN}}` and `*.{{DOMAIN}}`, a single CNAME on `_acme-challenge.{{DOMAIN}}` is sufficient.

---

## Renewal

NPM handles certificate renewal automatically. No manual intervention is required as long as:

- The `acmedns-registration.json` file remains in place and readable
- The CNAME record remains in DNS
- NPM has network access to `https://acmedns.realworld.net.au`

Check the **SSL Certificates** page periodically to confirm upcoming renewals complete successfully.

---

## Verification

After the certificate is issued, the **SSL Certificates** page status should show **Valid**.

If the certificate request or renewal fails:

```bash
docker compose logs npm
```

Common issues:

| Problem | Likely cause |
|---|---|
| DNS challenge failed | CNAME record missing or not yet propagated |
| Credentials file not found | Volume mount incorrect or file not at `/data/acmedns-registration.json` |
| API unreachable | Network issue or `dns_acmedns_api_url` misconfigured |
| Invalid credentials | Username/password in registration JSON do not match acmedns account |
