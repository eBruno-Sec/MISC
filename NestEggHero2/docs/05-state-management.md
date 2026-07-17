# State Management

## State classes

1. Ephemeral UI state
2. Persisted learning state
3. User preferences
4. Imported backup state
5. Sensitive or regulated data

## Rules

- Keep ephemeral state in memory.
- Store low-risk preferences locally.
- Use IndexedDB for larger offline learning state.
- Never store passwords, access tokens, full account numbers, tax IDs, or sensitive financial records in localStorage.
- Persist only data required to resume learning.
- Every persisted object requires `schemaVersion`, `createdAt`, and `updatedAt`.
- State transitions must be deterministic and testable.
- Provide migrations for supported historical schemas.
- Failed migrations must leave current state unchanged.
- Autosave must be debounced and recover from quota errors.
