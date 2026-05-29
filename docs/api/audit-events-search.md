# Audit Events Search API

## Route

- `GET /v1/audit/events/search`

## Headers

- `Authorization: Bearer <access_token>`
- `x-tenant-id`
- `x-project-id`

## Authorization

- Requires `SystemAdmin` role.
- Results are always scoped to the current `tenant_id` and `project_id`.
- `include_projectless=true` can include tenant-wide events that do not carry `project_id`.

## Query Parameters

- `action`: `query|view|export|permission_apply|login|config_change`
- `result`: `success|failure|denied`
- `actor_user_id`: exact user id match
- `resource_id_contains`: case-insensitive substring match
- `include_projectless`: optional boolean
- `limit`: defaults to `25`, capped at `100`

## Response

```json
{
  "events": [
    {
      "event_id": "01J...",
      "timestamp": "2026-03-29T12:34:56Z",
      "actor_user_id": "user-analyst",
      "action": "view",
      "result": "success",
      "tenant_id": "tenant-alpha",
      "project_id": "project-alpha",
      "resource_id": "project-context",
      "context": "project access granted",
      "data_fingerprint": null
    }
  ],
  "chain_valid": true,
  "total_matches": 3
}
```

## Notes

- Responses inherit API hardening headers: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a restrictive `Content-Security-Policy`.
- Phase 7 UAT coverage is implemented in `D:\Project\SDQP\apps\sdqp-api\tests\uat_phase7_hardening.rs`.
