# RWTS ACME DNS — DNS Setup and CNAME Configuration Reference

**Purpose:** Loaded during registration when users need CNAME configuration help, or when DNS verification fails.

---

## How DNS-01 Delegation Works

DNS-01 challenges let you prove domain ownership by publishing a TXT record under `_acme-challenge.<domain>`. The problem: ACME clients would need write access to your DNS zone for every renewal. Delegation avoids this.

**The delegation chain:**

1. Client registers `example.com` with the ACME DNS service — gets a UUID subdomain (e.g. `a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au`)
2. Client adds a one-time CNAME in their DNS zone: `_acme-challenge.example.com` → `a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au`
3. When an ACME client requests a certificate, Let's Encrypt queries `_acme-challenge.example.com`
4. The CNAME redirects the query to the acme-dns subdomain
5. acme-dns serves the TXT record containing the challenge token
6. Challenge passes — certificate issued

**Why this is useful:** The CNAME is set once and never touched again. All future renewals happen automatically through the acme-dns service without requiring any further DNS changes in the client's zone. The ACME client only needs credentials for the acme-dns service, not for the client's DNS provider.

---

## Wildcard Domain Handling

Wildcard certificates (`*.example.com`) use the same `_acme-challenge` prefix as non-wildcard certs. Strip the `*.` prefix when determining the CNAME name.

| Domain requested | CNAME name |
|---|---|
| `example.com` | `_acme-challenge.example.com` |
| `*.example.com` | `_acme-challenge.example.com` |
| `*.sub.example.com` | `_acme-challenge.sub.example.com` |

**Important:** `example.com` and `*.example.com` are treated as separate domains by the registration service — each requires its own acme-dns registration and gets its own UUID subdomain. However, the CNAME name for both is the same (`_acme-challenge.example.com`).

**SAN certificates covering both base and wildcard:** If requesting a certificate for `example.com` AND `*.example.com` in the same cert, you may need two CNAME records pointing to two different acme-dns subdomains. Not all DNS providers allow two CNAMEs on the same name — check your provider's behaviour. Some ACME clients handle this automatically; others require manual configuration.

---

## CNAME Record Examples

Replace `<subdomain>` with the UUID returned from registration (the `subdomain` field, not including the domain suffix). Replace `example.com` with the actual domain.

### Cloudflare

| Field | Value |
|---|---|
| Type | CNAME |
| Name | `_acme-challenge` |
| Target | `<subdomain>.acmedns.realworld.net.au` |
| Proxy status | **DNS only (grey cloud)** |

Cloudflare automatically appends the zone domain to the Name field, so entering `_acme-challenge` results in `_acme-challenge.example.com`.

**The proxy status MUST be set to DNS only (grey cloud).** If the orange cloud (proxied) is enabled, Cloudflare intercepts and proxies the DNS query through their network, which breaks DNS resolution of the CNAME target. Let's Encrypt cannot reach the acme-dns TXT record. This is the most common Cloudflare misconfiguration.

### Route 53

| Field | Value |
|---|---|
| Record name | `_acme-challenge.example.com` |
| Record type | CNAME |
| Value | `<subdomain>.acmedns.realworld.net.au` |
| TTL | `300` |

Route 53 requires the full record name including the zone domain.

### Generic Zone File

```
_acme-challenge.example.com. 300 IN CNAME <subdomain>.acmedns.realworld.net.au.
```

Note: trailing dots are required in zone file format. They mark names as fully qualified domain names (FQDNs). Without the trailing dot, the DNS server appends the zone name to the target, producing an incorrect record.

---

## TTL Recommendations

- **300 seconds (5 minutes)** is a good default for `_acme-challenge` CNAME records
- Lower TTL means faster propagation if you need to change the record, but generates more DNS queries
- If creating a new CNAME, TTL has little impact on initial propagation time — the record just needs to exist before Let's Encrypt queries it
- If replacing an existing record, the old TTL determines how long caches hold the old value

---

## Verification Commands

After adding the CNAME, verify it resolves correctly before attempting certificate issuance.

**Check the CNAME record exists:**

```bash
dig CNAME _acme-challenge.example.com
```

Expected output (relevant section):

```
;; ANSWER SECTION:
_acme-challenge.example.com. 300 IN CNAME a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au.
```

**Check using a specific resolver (bypasses local cache):**

```bash
dig CNAME _acme-challenge.example.com @8.8.8.8
```

**Check the TXT record that acme-dns serves (after at least one cert request):**

```bash
dig TXT a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au
```

Expected output once a challenge has been set:

```
;; ANSWER SECTION:
a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au. 1 IN TXT "challenge-token-value-here"
```

If this returns `NXDOMAIN` or no answer, either the CNAME is wrong or propagation hasn't completed.

**Trace the full resolution chain:**

```bash
dig +trace _acme-challenge.example.com
```

This shows each DNS hop and is useful for diagnosing where resolution breaks.

---

## Common Pitfalls

### Missing trailing dot in zone files

Zone file records use FQDN format. A target without a trailing dot has the zone name appended by the DNS server.

- Wrong: `... CNAME a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au`
- Correct: `... CNAME a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au.`

This only applies to raw zone files. Cloudflare, Route 53, and most web-based DNS interfaces handle FQDNs without trailing dots.

---

### Cloudflare proxy enabled on CNAME

The orange cloud (proxied) mode in Cloudflare must not be used on `_acme-challenge` records. When proxied, Cloudflare intercepts DNS queries and returns its own IP addresses rather than following the CNAME. Let's Encrypt then cannot reach the acme-dns TXT record and the challenge fails.

Set the CNAME to DNS only (grey cloud). This applies only to this specific record — other records in the zone can remain proxied.

---

### Propagation delays

DNS changes do not take effect instantly. How long propagation takes depends on:

- **For new records:** Generally 1–5 minutes for most resolvers, but up to several hours for some ISP resolvers
- **For changed records:** At minimum the TTL of the previous record — if the old TTL was 1 hour, cached resolvers may serve the old value for up to an hour

If `dig @8.8.8.8` shows the correct CNAME but `dig` (using your local resolver) does not, it's a local cache issue. Wait or flush the local DNS cache.

---

### Existing TXT record on `_acme-challenge`

A DNS name cannot have both a CNAME and a TXT record. If there is an existing `_acme-challenge.example.com TXT` record (from a previous manual DNS-01 challenge), the CNAME cannot be added alongside it.

Remove all existing TXT records on `_acme-challenge.example.com` before adding the CNAME.

---

### Subdomain confusion

The registration response contains a `subdomain` field (the UUID) and a `fulldomain` field. These are the **target** of the CNAME, not the name.

- CNAME **name:** `_acme-challenge.example.com` (always this format, based on your domain)
- CNAME **target:** `<uuid>.acmedns.realworld.net.au` (from the registration response `fulldomain`)

The UUID is not a replacement for `_acme-challenge` — it goes on the right-hand side of the CNAME.

---

### Wrong domain registered for wildcards

For `*.example.com`, register using `*.example.com` (with the asterisk). The registration service strips the `*.` prefix internally when generating the CNAME target, but the domain recorded in the system should match what you pass to your ACME client.

If your ACME client is configured to request `*.example.com` but you registered `example.com`, the credentials will not match and the DNS update will fail.
