# NIST Juliet Java 1.3 (B-010)

This directory pins, but does not vendor or silently download, NIST SARD test suite 111.
The upstream archive is 76,798,417 bytes and its SHA-256 is recorded in `manifest.json`.

The initial Apolaki slice covers every Java source file in the three CWE directories for which the
existing code-assisted engine has an explicit producer: CWE-327, CWE-328, and CWE-338. The blind scan
measures 131 Java files (38 + 55 + 38), including generated harnesses. B1 scoring covers every direct
`bad()` and `goodN()` oracle-bearing method in all 119 testcase files across variants 01-17. Generated
launchers and dispatch-only wrappers are excluded explicitly. All other Juliet domains remain
unsupported by this run; they are not dropped into an implied denominator.

Measured on the lane baseline image: a fresh blind scan took 3.555 seconds and post-seal scoring
took 3.984 seconds. The score has 329 method cases: 119 positive, 210 negative, and 0 skipped.

Setup on Windows PowerShell:

```powershell
./fetch.ps1 -Destination C:\path\to\juliet-java-1.3.zip
```

The adapter reads the ZIP directly; compilation and extraction are unnecessary. A run is labelled
`code-assisted (SAST)`, never DAST. The blind scan seals its checkpoint before the scorer is allowed
to open `Java/manifest.xml`. That pinned manifest is malformed by two duplicate `</testcase>` tags;
the scorer permits only the measured lines 50084 and 66737 and treats any other recovery as an
environment failure.
