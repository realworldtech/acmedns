# Proxmox VE — RWTS ACME DNS Platform Reference

**Purpose:** Loaded on demand when the user is configuring Proxmox VE to obtain Let's Encrypt certificates via the RWTS ACME DNS service.

---

## Prerequisites

- Proxmox VE 7.x or 8.x
- Shell access to the Proxmox host (or access to the web GUI)
- acmedns registration credentials for the domain:
  - `{{USERNAME}}` — acme-dns account username
  - `{{PASSWORD}}` — acme-dns account password
  - `{{SUBDOMAIN}}` — UUID returned by `/api/register`
  - `{{FULLDOMAIN}}` — `{{SUBDOMAIN}}.acmedns.realworld.net.au`
- CNAME record added in your DNS zone (see dns-setup reference)

---

## Configuration — Web GUI

### 1. Add a Let's Encrypt account (if not already done)

1. Navigate to **Datacenter → ACME**
2. Under **Accounts**, click **Add**
3. Enter a name (e.g. `default`) and your email address
4. Accept the Let's Encrypt Terms of Service and save

### 2. Add the acme-dns challenge plugin

1. Still on **Datacenter → ACME**, go to the **Challenge Plugins** section
2. Click **Add**
3. Fill in the fields:
   - **Plugin ID:** `acmedns`
   - **API:** select `acme-dns` from the dropdown
   - **API Data:**
     ```
     ACMEDNS_UPDATE_URL=https://acmedns.realworld.net.au/update
     ACMEDNS_USERNAME={{USERNAME}}
     ACMEDNS_PASSWORD={{PASSWORD}}
     ACMEDNS_SUBDOMAIN={{SUBDOMAIN}}
     ```
4. Click **Add** to save

### 3. Configure the node certificate

1. Navigate to **Node → System → Certificates**
2. Under the **ACME** section, click **Add**
3. Set:
   - **Challenge Type:** `DNS`
   - **Plugin:** `acmedns`
   - **Domain:** `{{DOMAIN}}`
4. Click **Add**, then click **Order Certificates Now**

Proxmox will call the acme-dns `/update` endpoint, wait for propagation, and retrieve the certificate. The web interface reloads automatically once the certificate is issued.

---

## Configuration — CLI

### Register the acme-dns plugin

```bash
pvenode acme plugin add dns acmedns \
  --api acme-dns \
  --data "ACMEDNS_UPDATE_URL=https://acmedns.realworld.net.au/update,ACMEDNS_USERNAME={{USERNAME}},ACMEDNS_PASSWORD={{PASSWORD}},ACMEDNS_SUBDOMAIN={{SUBDOMAIN}}"
```

### Register a Let's Encrypt account (if not already done)

```bash
pvenode acme account register default your-email@example.com
```

### Order the certificate

```bash
pvenode acme cert order --domain {{DOMAIN}} --plugin acmedns
```

Proxmox will contact Let's Encrypt, perform the DNS-01 challenge via the acme-dns plugin, and install the certificate.

---

## Plugin Configuration Storage

The plugin definition is stored in `/etc/pve/acme/plugins.cfg`. This file is managed by Proxmox — edit it via the GUI or `pvenode` CLI rather than directly.

---

## Important: Update URL

`ACMEDNS_UPDATE_URL` must be set to:

```
https://acmedns.realworld.net.au/update
```

Use the root `/update` path exactly. Do **not** use `/api/update` — that path does not exist on this service.

---

## Renewal

Renewal is fully automatic. Proxmox installs a systemd timer (`pvenode-acme-cert-renew.timer`) that checks certificate expiry and renews before expiry. No manual action is required.

To check the timer status:

```bash
systemctl status pvenode-acme-cert-renew.timer
```

---

## Verification

### GUI

Navigate to **Node → System → Certificates**. The certificate entry shows its status (`Valid`) and the expiry date.

### CLI

**View certificate details:**

```bash
pvenode acme cert info
```

**Force a manual renewal (for testing):**

```bash
pvenode acme cert renew
```

**Inspect the installed certificate directly:**

```bash
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -dates -subject
```

---

## Common Issues

### Challenge fails with connection error

- Confirm `ACMEDNS_UPDATE_URL` is `https://acmedns.realworld.net.au/update` with no trailing slash and no `/api/` prefix
- Confirm the Proxmox host can reach `acmedns.realworld.net.au` over HTTPS (check firewall rules)

### Certificate not trusted by browsers

- Confirm the CNAME record is in place: `_acme-challenge.{{DOMAIN}} CNAME {{FULLDOMAIN}}`
- Run `dig CNAME _acme-challenge.{{DOMAIN}}` to verify propagation before ordering

### Plugin not listed in GUI dropdown

- Confirm the plugin was added with `pvenode acme plugin add` or via the GUI — the dropdown only shows saved plugins
- Run `pvenode acme plugin list` to verify the plugin exists
