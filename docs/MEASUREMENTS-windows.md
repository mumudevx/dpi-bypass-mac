# Windows measurements

**No Windows measurement exists yet.** Nothing in this repository has run on a Windows machine.

The ladder in `internal/config/embed/turkey.toml` was measured on **macOS** (Türk Telekom AS9121, Kayseri, 2026-09-02). Windows has a different TCP stack; those numbers do not transfer.

## What would establish a Windows measurement

- A Windows 11 machine on a live censored line (Türk Telekom or equivalent).
- Running `dpb tune` on that machine to measure the same block and emitters.
- The resulting ladder, stored and committed the same way the macOS numbers are.

Until that happens, every emitter choice on Windows is unverified. Use the first `-windows-preview` release as a release candidate, not a verified install. Read "Reporting a result" in the main README before filing an issue.
