# Security

**Last fact-check:** 2026-07-16

Use NIST SP 800-218 SSDF Version 1.1 as the current final publication. Treat NIST SP 800-218 Revision 1 / SSDF 1.2 as draft material until finalized. Use OWASP ASVS 5.0.0 as the application-security verification baseline.

## Controls

- Threat-model imports, authentication, calculators, authoring, analytics, and third parties.
- Validate at trust boundaries and sanitize rich text with an allowlist.
- Apply a restrictive Content Security Policy.
- Prevent prototype pollution during merges.
- Cap JSON upload size, depth, object count, and string length.
- Reject unsupported schemas before migration.
- Keep secrets out of client bundles and exports.
- Scan dependencies and maintain security logging without sensitive payloads.

## Sources

- https://csrc.nist.gov/pubs/sp/800/218/final
- https://csrc.nist.gov/pubs/sp/800/218/r1/ipd
- https://owasp.org/www-project-application-security-verification-standard/
