# Reference Architecture

Recommended layers:

- Content layer
- Presentation layer
- Domain logic
- Calculator engine
- State persistence
- Import/export
- Analytics adapter
- Authentication adapter
- Content management
- Search
- Observability

Keep calculator formulas and financial rules in versioned domain modules. UI components should consume typed outputs rather than reproduce formulas.
