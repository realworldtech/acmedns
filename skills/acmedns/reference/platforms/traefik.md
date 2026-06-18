# RWTS ACME DNS — Traefik Platform Reference

**Purpose:** Loaded when the user chooses Traefik as their ACME client platform. Covers Docker Compose configuration via container labels and command args, credential file setup, and verification.

---

## Prerequisites

- Docker and Docker Compose installed
- Traefik v3.x running as reverse proxy
- acmedns registration credentials for each domain:
  - `{{SUBDOMAIN}}` — UUID returned by `/api/register`
  - `{{USERNAME}}` — acme-dns account username
  - `{{PASSWORD}}` — acme-dns account password
  - `{{FULLDOMAIN}}` — `{{SUBDOMAIN}}.acmedns.realworld.net.au`
- CNAME record added in your DNS zone (see dns-setup reference)

---

## How It Works

Traefik has a built-in `acme-dns` DNS challenge provider. When a router label requests a certificate, Traefik:

1. Calls the acme-dns `/update` endpoint with the DNS-01 challenge token
2. Uses the configured `resolvers` to check DNS propagation
3. Notifies Let's Encrypt to verify the challenge
4. Stores the issued certificate in `acme.json`

Credentials for each domain are read from a JSON file (`acmedns.json`) mounted into the Traefik container. No plugin or external hook is required.

---

## Configuration

Traefik's static configuration (entrypoints, certificate resolvers) is defined via command-line flags on the Traefik container. Per-service routing is configured via Docker container labels. This avoids maintaining a separate `traefik.yml` file.

### acmedns.json (credential file)

This file maps each domain to its acme-dns credentials. The key is the domain name exactly as Traefik will request the certificate for it.

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

**Wildcard plus base domain (separate registrations, separate entries):**

```json
{
  "example.com": {
    "username": "{{USERNAME_BASE}}",
    "password": "{{PASSWORD_BASE}}",
    "fulldomain": "{{FULLDOMAIN_BASE}}",
    "subdomain": "{{SUBDOMAIN_BASE}}",
    "allowfrom": []
  },
  "*.example.com": {
    "username": "{{USERNAME_WILDCARD}}",
    "password": "{{PASSWORD_WILDCARD}}",
    "fulldomain": "{{FULLDOMAIN_WILDCARD}}",
    "subdomain": "{{SUBDOMAIN_WILDCARD}}",
    "allowfrom": []
  }
}
```

`example.com` and `*.example.com` are separate registrations — each has its own UUID and its own credentials. They must both appear in `acmedns.json` if Traefik will be requesting both.

**The key in `acmedns.json` must match the domain Traefik is requesting the certificate for.** If Traefik requests a SAN cert for `example.com` and `*.example.com`, both keys must be present.

Mount this file read-only into the container. Do not commit it to version control — it contains credentials.

---

### docker-compose.yml — Traefik service

The certificate resolver and all static configuration is defined via `command` args on the Traefik container:

```yaml
services:
  traefik:
    image: traefik:v3.6
    restart: unless-stopped
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.acmedns.acme.email=your-email@example.com"
      - "--certificatesresolvers.acmedns.acme.storage=/certs/acme.json"
      - "--certificatesresolvers.acmedns.acme.dnschallenge.provider=acme-dns"
      - "--certificatesresolvers.acmedns.acme.dnschallenge.delaybeforecheck=10"
      - "--certificatesresolvers.acmedns.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53"
    environment:
      - ACME_DNS_API_BASE=https://acmedns.realworld.net.au
      - ACME_DNS_STORAGE_PATH=/acme-dns-accounts/acmedns.json
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik-certs:/certs
      - ./acmedns.json:/acme-dns-accounts/acmedns.json:ro
    networks:
      - proxy

volumes:
  traefik-certs:

networks:
  proxy:
    external: true
```

| Command flag | Purpose |
|---|---|
| `providers.docker` | Discover services and labels from Docker |
| `providers.docker.exposedbydefault=false` | Only route services with `traefik.enable=true` |
| `entrypoints.web` / `websecure` | HTTP (80) and HTTPS (443) listeners |
| `certificatesresolvers.acmedns.acme.email` | Contact email for Let's Encrypt account |
| `certificatesresolvers.acmedns.acme.storage` | Path inside container for certificate storage |
| `dnschallenge.provider=acme-dns` | Use the built-in acme-dns provider |
| `dnschallenge.delaybeforecheck` | Seconds to wait after updating DNS before verifying. `10` is usually sufficient; increase if propagation is slow. |
| `dnschallenge.resolvers` | **External DNS resolvers** for propagation checks. Required for internal/private domains where the local resolver cannot see the acme-dns records. |

| Environment variable | Value |
|---|---|
| `ACME_DNS_API_BASE` | URL of the acme-dns `/update` endpoint base (no trailing slash) |
| `ACME_DNS_STORAGE_PATH` | Path inside the Traefik container to the credential file |

---

### docker-compose.yml — Application service labels

Each service that needs a TLS certificate is configured via Docker labels:

```yaml
services:
  my-service:
    image: my-image:latest
    restart: unless-stopped
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-service.rule=Host(`example.com`) || Host(`www.example.com`)"
      - "traefik.http.routers.my-service.entrypoints=websecure"
      - "traefik.http.routers.my-service.tls=true"
      - "traefik.http.routers.my-service.tls.certresolver=acmedns"
      - "traefik.http.routers.my-service.tls.domains[0].main=example.com"
      - "traefik.http.routers.my-service.tls.domains[0].sans=*.example.com"
      - "traefik.http.services.my-service.loadbalancer.server.port=8080"

networks:
  proxy:
    external: true
```

**Label notes:**

| Label | Purpose |
|---|---|
| `traefik.enable=true` | Exposes this service to Traefik (required when `exposedbydefault=false`) |
| `tls.certresolver=acmedns` | Tells Traefik to use the `acmedns` resolver defined in the command args |
| `tls.domains[0].main` | Primary domain for the certificate |
| `tls.domains[0].sans` | Additional SANs — use this for wildcard coverage |

If you only need a single non-wildcard domain, omit the `tls.domains` labels and let Traefik infer the domain from the `Host()` router rule.

---

## Alternative: traefik.yml static config

If the user prefers a static config file over command args, the certificate resolver can be defined in `traefik.yml` instead. Mount it at `/traefik.yml:ro` and remove the equivalent `--certificatesresolvers.*` and `--entrypoints.*` command args.

```yaml
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false

certificatesResolvers:
  acmedns:
    acme:
      email: your-email@example.com
      storage: /certs/acme.json
      dnsChallenge:
        provider: acme-dns
        delayBeforeCheck: 10
        resolvers:
          - "1.1.1.1:53"
          - "8.8.8.8:53"
```

Add the volume mount to the Traefik service:

```yaml
    volumes:
      - ./traefik/traefik.yml:/traefik.yml:ro
```

---

## Where to Put Each File

| File | Location | Notes |
|---|---|---|
| `acmedns.json` | Mounted at the path set in `ACME_DNS_STORAGE_PATH` | Mount read-only (`:ro`). Keep outside version control. |
| Labels | On each service in `docker-compose.yml` | One `certresolver` label per router |
| `traefik.yml` (optional) | Mounted at `/traefik.yml` inside the container | Only if using static config file instead of command args |

---

## DNS Resolver Configuration

**This is critical for internal/private domains.** When Traefik runs inside a network whose DNS resolver cannot see the acme-dns CNAME or TXT records (e.g. a corporate LAN, a Docker network with a local DNS server, or a split-horizon DNS setup), the DNS propagation check will fail even though the records are correct on the public internet.

The `dnschallenge.resolvers` setting tells Traefik to bypass the local resolver and query external DNS servers directly:

```
--certificatesresolvers.acmedns.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53
```

This is included in the Docker Compose example above. **Always include this setting** — it is harmless for public domains and essential for internal ones.

---

## Renewal

Renewal is fully automatic. Traefik monitors certificate expiry and renews via the acme-dns provider before expiry. No cron job or manual intervention is needed.

The renewed certificate is written back to `acme.json` (the `storage` path). As long as that volume persists across container restarts, certificates survive redeployments without re-issuance.

---

## Verification

Check Traefik logs for ACME and certificate activity:

```bash
docker compose logs traefik | grep -i "acme\|certificate\|dns"
```

Inspect the issued certificate directly:

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -dates -subject
```

Expected output (Let's Encrypt certificate):

```
notBefore=Mar 24 00:00:00 2026 GMT
notAfter=Jun 22 23:59:59 2026 GMT
subject=CN=example.com
```

Check `acme.json` contains entries for your domains (file is on the Traefik host at the volume mount path):

```bash
cat /path/to/acme.json | python3 -m json.tool | grep -i "example.com"
```

---

## Common Issues

### Certificate not being issued

- Confirm the `acmedns.json` key matches the domain exactly, including `*.` prefix for wildcards
- Confirm `ACME_DNS_API_BASE` has no trailing slash
- Confirm the CNAME record is in place and resolving (`dig CNAME _acme-challenge.{{DOMAIN}}`)
- Check Traefik logs for the specific error — `acme-dns` errors surface there

### DNS propagation check fails on internal network

- Ensure `dnschallenge.resolvers` is set to external resolvers (`1.1.1.1:53,8.8.8.8:53`)
- Verify from the Traefik host that external resolvers are reachable: `dig @1.1.1.1 _acme-challenge.{{DOMAIN}}`
- If the network blocks outbound DNS (port 53), resolvers won't work — you may need to allowlist the resolver IPs in your firewall

### Traefik container can't read acmedns.json

- Check the mount path in `docker-compose.yml` matches `ACME_DNS_STORAGE_PATH`
- Ensure the file exists on the host before starting the container
- The `:ro` flag is fine — Traefik reads but does not write this file

### Certificate valid but wrong domain

- The `tls.domains[0].main` label overrides the domain inferred from the `Host()` rule
- If both are set, ensure they are consistent
- For SAN certs covering base and wildcard, both must appear in `acmedns.json`
