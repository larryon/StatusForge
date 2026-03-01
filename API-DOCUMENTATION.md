# Uptime Kuma REST API

## Overview

Uptime Kuma provides a RESTful API (v1) for programmatic access to monitors, notifications, maintenance, tags, status pages, Docker hosts, users, API keys, and settings.

**Base URL**: `https://your-instance/api/v1`

> **Full interactive documentation** is available at `/api-docs` on your instance (enabled in dev mode or by setting `EXPOSE_API_DOCS=1`). The OpenAPI spec is at [`server/openapi/openapi.yaml`](server/openapi/openapi.yaml).

---

## Authentication

All `/api/v1/*` endpoints require an API key in the `Authorization` header:

```
Authorization: Bearer uk{id}_{key}
```

Example:
```
Authorization: Bearer uk5_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ
```

Create API keys in **Settings → API Keys** in the web UI. Each key is assigned scopes that control which endpoints it can access.

---

## Roles

| Role | Description |
|------|-------------|
| **admin** | Full access to all resources, including users and settings |
| **read-only** | Read-only access to monitors, notifications, status pages, maintenance, tags, uptime, and Docker hosts |

API keys inherit the role of the user who created them. Admin-only scopes are automatically stripped from keys owned by non-admin users.

---

## Scopes

API keys use scopes to restrict access. Format: `resource:action`.

| Scope | Admin Only |
|-------|-----------|
| `monitors:read` | No |
| `monitors:write` | No |
| `notifications:read` | No |
| `notifications:write` | No |
| `status-pages:read` | No |
| `status-pages:write` | No |
| `maintenance:read` | No |
| `maintenance:write` | No |
| `tags:read` | No |
| `tags:write` | No |
| `uptime:read` | No |
| `docker:read` | No |
| `docker:write` | No |
| `api-keys:read` | No |
| `api-keys:write` | No |
| `users:read` | **Yes** |
| `users:write` | **Yes** |
| `settings:read` | **Yes** |
| `settings:write` | **Yes** |

### Scope Presets

| Preset | Scopes Included |
|--------|----------------|
| `read-only` | All `:read` scopes (monitors, notifications, status-pages, maintenance, tags, uptime, docker) |
| `read-write` | All `:read` + `:write` scopes except users and settings |
| `full-access` | All scopes (including admin-only scopes) |

---

## Rate Limiting

All API endpoints are rate-limited to **60 requests per minute** per API key. Exceeding this returns `429 Too Many Requests`.

---

## Response Format

All responses follow this JSON structure:

```json
{
    "ok": true,
    "msg": "Success",
    "data": { }
}
```

Error responses:
```json
{
    "ok": false,
    "msg": "Error description"
}
```

---

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request / validation error |
| 401 | Missing or invalid API key |
| 403 | Insufficient permissions or scope |
| 404 | Resource not found |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## Endpoint Summary

### Info

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/info` | `monitors:read` | API info, version, and effective scopes |

### Monitors

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/monitors` | `monitors:read` | List all monitors |
| POST | `/api/v1/monitors` | `monitors:write` | Create a monitor (admin) |
| GET | `/api/v1/monitors/{id}` | `monitors:read` | Get monitor by ID |
| PATCH | `/api/v1/monitors/{id}` | `monitors:write` | Update a monitor (admin) |
| DELETE | `/api/v1/monitors/{id}` | `monitors:write` | Delete a monitor (admin) |
| POST | `/api/v1/monitors/{id}/pause` | `monitors:write` | Pause a monitor (admin) |
| POST | `/api/v1/monitors/{id}/resume` | `monitors:write` | Resume a monitor (admin) |
| GET | `/api/v1/monitors/{id}/beats` | `uptime:read` | Get heartbeat history |
| GET | `/api/v1/monitors/{id}/uptime` | `uptime:read` | Get monitor uptime percentage |

### Notifications

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/notifications` | `notifications:read` | List all notifications |
| POST | `/api/v1/notifications` | `notifications:write` | Create a notification |
| GET | `/api/v1/notifications/{id}` | `notifications:read` | Get notification by ID |
| PATCH | `/api/v1/notifications/{id}` | `notifications:write` | Update a notification |
| DELETE | `/api/v1/notifications/{id}` | `notifications:write` | Delete a notification |

### Tags

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/tags` | `tags:read` | List all tags |
| POST | `/api/v1/tags` | `tags:write` | Create a tag |
| GET | `/api/v1/tags/{id}` | `tags:read` | Get tag by ID |
| PATCH | `/api/v1/tags/{id}` | `tags:write` | Update a tag |
| DELETE | `/api/v1/tags/{id}` | `tags:write` | Delete a tag |

### Maintenance

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/maintenance` | `maintenance:read` | List maintenance windows |
| POST | `/api/v1/maintenance` | `maintenance:write` | Create a maintenance window |
| GET | `/api/v1/maintenance/{id}` | `maintenance:read` | Get maintenance by ID |
| PATCH | `/api/v1/maintenance/{id}` | `maintenance:write` | Update a maintenance window (admin) |
| DELETE | `/api/v1/maintenance/{id}` | `maintenance:write` | Delete a maintenance window (admin) |
| POST | `/api/v1/maintenance/{id}/pause` | `maintenance:write` | Pause a maintenance window |
| POST | `/api/v1/maintenance/{id}/resume` | `maintenance:write` | Resume a maintenance window |
| GET | `/api/v1/maintenance/{id}/monitors` | `maintenance:read` | Get monitors assigned to maintenance |
| PUT | `/api/v1/maintenance/{id}/monitors` | `maintenance:write` | Set monitors for maintenance |
| GET | `/api/v1/maintenance/{id}/status-pages` | `maintenance:read` | Get status pages assigned to maintenance |
| PUT | `/api/v1/maintenance/{id}/status-pages` | `maintenance:write` | Set status pages for maintenance |

### Status Pages

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/status-pages` | `status-pages:read` | List all status pages |
| POST | `/api/v1/status-pages` | `status-pages:write` | Create a status page (admin) |
| GET | `/api/v1/status-pages/{slug}` | `status-pages:read` | Get status page by slug |
| PATCH | `/api/v1/status-pages/{slug}` | `status-pages:write` | Update a status page (admin) |
| DELETE | `/api/v1/status-pages/{slug}` | `status-pages:write` | Delete a status page (admin) |
| POST | `/api/v1/status-pages/{slug}/incidents` | `status-pages:write` | Create an incident |
| DELETE | `/api/v1/status-pages/{slug}/incidents/{incidentId}` | `status-pages:write` | Delete an incident |

### Uptime

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/uptime` | `uptime:read` | Uptime summary for all monitors |

### Docker Hosts

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/docker-hosts` | `docker:read` | List Docker hosts |
| POST | `/api/v1/docker-hosts` | `docker:write` | Create a Docker host |
| GET | `/api/v1/docker-hosts/{id}` | `docker:read` | Get Docker host by ID |
| PATCH | `/api/v1/docker-hosts/{id}` | `docker:write` | Update a Docker host |
| DELETE | `/api/v1/docker-hosts/{id}` | `docker:write` | Delete a Docker host |

### Users (Admin Only)

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/users` | `users:read` | List all users |
| POST | `/api/v1/users` | `users:write` | Create a user |
| GET | `/api/v1/users/{id}` | `users:read` | Get user by ID |
| PATCH | `/api/v1/users/{id}` | `users:write` | Update a user |
| DELETE | `/api/v1/users/{id}` | `users:write` | Delete a user |
| POST | `/api/v1/users/{id}/reset-password` | `users:write` | Reset user password |

### API Keys

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/api-keys` | `api-keys:read` | List API keys |
| POST | `/api/v1/api-keys` | `api-keys:write` | Create an API key |
| GET | `/api/v1/api-keys/scopes` | `api-keys:read` | List available scopes |
| DELETE | `/api/v1/api-keys/{id}` | `api-keys:write` | Delete an API key |
| POST | `/api/v1/api-keys/{id}/enable` | `api-keys:write` | Enable an API key |
| POST | `/api/v1/api-keys/{id}/disable` | `api-keys:write` | Disable an API key |

### Settings (Admin Only)

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/settings` | `settings:read` | Get settings |
| PATCH | `/api/v1/settings` | `settings:write` | Update settings |

---

## Quick Examples

### List all monitors

```bash
curl -s https://your-instance/api/v1/monitors \
  -H "Authorization: Bearer uk5_aB3cD4eF5gH6iJ7kL8mN9oP0q"
```

### Create a monitor

```bash
curl -s -X POST https://your-instance/api/v1/monitors \
  -H "Authorization: Bearer uk5_aB3cD4eF5gH6iJ7kL8mN9oP0q" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Website",
    "type": "http",
    "url": "https://example.com",
    "interval": 60
  }'
```

### Get API info

```bash
curl -s https://your-instance/api/v1/info \
  -H "Authorization: Bearer uk5_aB3cD4eF5gH6iJ7kL8mN9oP0q"
```

---

> For detailed request/response schemas, parameter descriptions, and interactive testing, visit the **Swagger UI** at `/api-docs` on your Uptime Kuma instance.
