# JSON Backup Specification

## Filename

`NestEggHero_backup_YYYY-MM-DD.json`

## Required envelope

```json
{
  "format": "nestegghero-backup",
  "schemaVersion": "1.0.0",
  "exportedAt": "2026-07-16T00:00:00Z",
  "appVersion": "1.0.0",
  "checksum": "sha256-base64",
  "payload": {}
}
```

## Payload scope

Allowed:

- Bookmarks
- Read/unread state
- Article progress
- Highlights
- Quiz attempts and scores
- Learning goals
- Badges
- Reading lists
- Theme and accessibility preferences

Excluded by default:

- Authentication secrets
- Bank credentials
- Full financial account data
- Government identifiers
- Payment-card data
- Analytics identifiers

## Import pipeline

1. Verify file size and MIME expectations.
2. Read as text.
3. Parse JSON inside a guarded operation.
4. Validate the envelope.
5. Validate against JSON Schema.
6. Recalculate checksum.
7. Reject unsupported future major versions.
8. Migrate supported older versions.
9. Show a preview of imported categories.
10. Ask whether to merge or replace.
11. Apply atomically.
12. Confirm success.

Errors must preserve the existing state.
