# Design System

## Tokens

Use semantic tokens rather than raw values:

- `surface-page`
- `surface-card`
- `surface-elevated`
- `text-primary`
- `text-secondary`
- `text-inverse`
- `border-default`
- `action-primary`
- `action-secondary`
- `status-success`
- `status-warning`
- `status-danger`
- `focus-ring`

## Typography

- Default body: 16–18px
- Reading content: 18px preferred
- Line height: 1.5–1.75
- Maximum article measure: 65–75 characters
- Never use all caps for long text
- Do not rely on ultra-light font weights

## Spacing

Use an 8px base rhythm with 4px exceptions for compact internal spacing.

## Motion

- Micro-interaction: 120–200ms
- View transition: 180–300ms
- Avoid decorative motion above 400ms
- Disable nonessential motion under `prefers-reduced-motion`

## Themes

Light and dark themes must share semantic meaning and pass contrast checks independently.
