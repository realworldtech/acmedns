# RWTS ACME DNS — API Reference

**Purpose:** Loaded on demand for troubleshooting and API questions about the RWTS ACME DNS registration service.

---

## Base URL

```
https://acmedns.realworld.net.au
```

## URL Convention

All registration API endpoints use the `/api/` prefix externally. Traefik strips the `/api` prefix before routing requests to the Flask application internally.

| External URL | Internal Flask route |
|---|---|
| `https://acmedns.realworld.net.au/api/register` | `/register` |
| `https://acmedns.realworld.net.au/api/health` | `/health` |
| `https://acmedns.realworld.net.au/update` | `/update` (direct to acme-dns, no stripping) |

---

## Authentication

**Public endpoints** — use the `X-API-Key` header:

```
X-API-Key: acmedns_your-api-key-here
```

**Admin endpoints** — use `Authorization: Bearer` with the master key:

```
Authorization: Bearer your-master-key-here
```

Both missing and invalid credentials return `401`. The error message does not distinguish between the two cases.

---

## Public Endpoints

### POST /api/register

Register a new domain with acme-dns. The registration allocates a dedicated subdomain for DNS-01 challenge records.

**Request:**

```bash
curl -X POST https://acmedns.realworld.net.au/api/register \
  -H "X-API-Key: acmedns_your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Wildcard domains are supported:

```bash
curl -X POST https://acmedns.realworld.net.au/api/register \
  -H "X-API-Key: acmedns_your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "*.example.com"}'
```

**Response (200):**

```json
{
  "subdomain": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "username": "abcdef01-2345-6789-abcd-ef0123456789",
  "password": "SomeRandomPassword123",
  "fulldomain": "a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au",
  "allowfrom": []
}
```

The response is proxied directly from acme-dns. **Credentials (`username` and `password`) are only returned once** — store them immediately. They cannot be retrieved again.

For wildcard domains (`*.example.com`), the CNAME record should point `_acme-challenge.example.com` (without the `*.` prefix) to the returned `fulldomain`.

---

### POST /api/lookup

Look up the ACME DNS configuration for a previously registered domain. Returns configuration details and DNS setup instructions, but does **not** return acme-dns username or password.

**Request:**

```bash
curl -X POST https://acmedns.realworld.net.au/api/lookup \
  -H "X-API-Key: acmedns_your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Response (200):**

```json
{
  "domain": "example.com",
  "acme_dns_server": "acmedns.realworld.net.au",
  "subdomain": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "cname_record": {
    "name": "_acme-challenge.example.com",
    "value": "a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au",
    "type": "CNAME"
  },
  "registration_info": {
    "registered_at": "2026-03-24T10:00:00",
    "key_name": "My API Key",
    "total_registrations": 1
  },
  "instructions": {
    "step1": "Add this CNAME record to your DNS: _acme-challenge.example.com CNAME a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au",
    "step2": "Configure your ACME client to use DNS-01 challenge with acme-dns",
    "step3": "Use the subdomain and your API key for certificate requests"
  }
}
```

Returns `404` if no registration exists for the domain under the current API key.

---

### GET /api/health

Health check. Does not require authentication.

**Request:**

```bash
curl https://acmedns.realworld.net.au/api/health
```

**Response (200):**

```json
{
  "status": "healthy",
  "database": "ok",
  "acme_dns": "ok"
}
```

`acme_dns` reflects connectivity to the upstream acme-dns service. Returns `500` with `"status": "unhealthy"` if either check fails.

---

### GET /api/info

Returns metadata about the API key making the request. Does not return the key value itself.

**Request:**

```bash
curl https://acmedns.realworld.net.au/api/info \
  -H "X-API-Key: acmedns_your-api-key-here"
```

**Response (200):**

```json
{
  "name": "My API Key",
  "email": "user@example.com",
  "organization": "Example Org",
  "created_at": "2026-03-01T09:00:00",
  "expires_at": "2027-03-01T09:00:00",
  "usage_count": 42,
  "last_used_at": "2026-03-24T10:00:00",
  "registration_count": 5
}
```

`expires_at` is `null` for non-expiring keys. `email` and `organization` are `null` if not set at key creation.

---

## Admin Endpoints

All admin endpoints require `Authorization: Bearer <master-key>`.

### POST /api/admin/keys

Create a new API key.

**Request:**

```bash
curl -X POST https://acmedns.realworld.net.au/api/admin/keys \
  -H "Authorization: Bearer your-master-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Client",
    "email": "client@example.com",
    "organization": "Example Org",
    "expires_days": 365
  }'
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Display name for the key |
| `email` | No | Contact email |
| `organization` | No | Organisation name |
| `expires_days` | No | Expiry in days (1–3650). Omit for no expiry. |

**Response (201):**

```json
{
  "key_id": "key_a1b2c3d4e5f6a7b8",
  "api_key": "acmedns_SomeGeneratedKeyValue",
  "name": "My Client",
  "expires_at": "2027-03-24T10:00:00",
  "message": "Store this API key securely - it will not be shown again"
}
```

**The `api_key` value is only returned once.** Store it immediately.

---

### GET /api/admin/keys

List all API keys. Actual key values are never returned.

**Request:**

```bash
curl https://acmedns.realworld.net.au/api/admin/keys \
  -H "Authorization: Bearer your-master-key-here"
```

**Response (200):**

```json
[
  {
    "key_id": "key_a1b2c3d4e5f6a7b8",
    "name": "My Client",
    "email": "client@example.com",
    "organization": "Example Org",
    "created_at": "2026-03-01T09:00:00",
    "expires_at": "2027-03-01T09:00:00",
    "is_active": 1,
    "usage_count": 42,
    "last_used_at": "2026-03-24T10:00:00"
  }
]
```

---

### DELETE /api/admin/keys/\<key_id\>

Revoke an API key. Sets `is_active` to `0` — does not delete the record.

**Request:**

```bash
curl -X DELETE https://acmedns.realworld.net.au/api/admin/keys/key_a1b2c3d4e5f6a7b8 \
  -H "Authorization: Bearer your-master-key-here"
```

**Response (200):**

```json
{
  "message": "API key revoked"
}
```

Returns `404` if `key_id` does not exist.

---

### GET /api/admin/registrations

List registrations. Returns the most recent 100 records, ordered by `created_at` descending.

**Request:**

```bash
curl https://acmedns.realworld.net.au/api/admin/registrations \
  -H "Authorization: Bearer your-master-key-here"
```

**Response (200):**

```json
[
  {
    "id": 1,
    "api_key_id": "key_a1b2c3d4e5f6a7b8",
    "subdomain": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "domain_hint": "example.com",
    "client_ip": "203.0.113.10",
    "created_at": "2026-03-24T10:00:00",
    "key_name": "My Client",
    "organization": "Example Org"
  }
]
```

---

### DELETE /api/admin/registrations/\<id\>

Delete a registration record by its integer ID.

**Request:**

```bash
curl -X DELETE https://acmedns.realworld.net.au/api/admin/registrations/1 \
  -H "Authorization: Bearer your-master-key-here"
```

**Response (200):**

```json
{
  "message": "Registration revoked successfully"
}
```

Returns `404` if the registration ID does not exist.

---

### GET /api/admin/stats

Service statistics.

**Request:**

```bash
curl https://acmedns.realworld.net.au/api/admin/stats \
  -H "Authorization: Bearer your-master-key-here"
```

**Response (200):**

```json
{
  "total_keys": 10,
  "active_keys": 8,
  "total_registrations": 150,
  "registrations_last_24h": 3,
  "top_users": [
    {
      "name": "My Client",
      "organization": "Example Org",
      "registration_count": 42
    }
  ]
}
```

`top_users` returns up to 10 entries, ordered by `registration_count` descending.

---

## Rate Limits

Rate limit headers are included in all responses (`X-RateLimit-*`). On breach, the response is `429` with a `retry_after` field (seconds).

| Endpoint | Limit |
|---|---|
| `POST /api/register` | 10 / minute |
| `GET /api/health` | 30 / minute |
| `GET /api/info` | 30 / minute |
| `POST /api/lookup` | 20 / minute |
| `POST /api/admin/keys` | 10 / hour |
| `GET /api/admin/keys` | 30 / hour |
| `DELETE /api/admin/keys/<key_id>` | 20 / hour |
| `GET /api/admin/registrations` | 60 / hour |
| `DELETE /api/admin/registrations/<id>` | 30 / hour |
| `GET /api/admin/stats` | 100 / hour |
| Default (all other routes) | 200 / day, 50 / hour |

---

## Error Responses

All errors return JSON with an `"error"` field.

| Status | Meaning |
|---|---|
| `400` | Validation error (invalid domain format, missing required field, out-of-range value) |
| `401` | Authentication failure — used for both missing and invalid credentials |
| `404` | Resource not found |
| `429` | Rate limit exceeded — includes `retry_after` (seconds) |
| `500` | Internal server error |
| `503` | Upstream service (acme-dns) unavailable |

Example `429` response:

```json
{
  "error": "Rate limit exceeded",
  "message": "You have exceeded the rate limit. Try again later.",
  "retry_after": 47
}
```

---

## The /update Endpoint

> **Important:** The `/update` endpoint is at the root path — `https://acmedns.realworld.net.au/update` — **not** under `/api/`.

This is the native acme-dns endpoint that ACME clients call directly when performing DNS record updates during challenge validation. It is routed by Traefik straight to the acme-dns service without passing through the registration API.

The `/api/*` registration API is a separate management layer for provisioning and key management. These two layers serve different purposes and must not be confused.
