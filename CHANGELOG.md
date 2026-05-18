# Changelog

All notable changes to `pdf-defang` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-18

Initial release.

### Added — Core API

- `sanitize(path, return_report=False, password=None, level="strict")` -
  strips active content from a PDF in place. Two levels:

  - `level="strict"` (default) - strips every form of active content:
    - Document-level JavaScript (`/Names → /JavaScript`)
    - Embedded files (`/Names → /EmbeddedFiles`)
    - Open actions (`/OpenAction`)
    - Document and page-level auto-actions (`/AA`)
    - XFA forms (`/AcroForm → /XFA`)
    - Form calculation order (`/AcroForm → /CO`)
    - Dangerous annotation actions: `/JavaScript`, `/Launch`, `/ImportData`,
      `/SubmitForm`, `/ResetForm`, `/Rendition`, `/GoToR`, `/GoToE`,
      `/Movie`, `/Sound`
    - Annotation-level auto-actions and JS (`/AA`, `/JS`)
    - Unsafe URI actions: `javascript:`, `file:`, `data:`, `vbscript:`,
      UNC paths, and any other non-whitelisted scheme. Standard hyperlinks
      (`http`, `https`, `mailto`, `tel`, `ftp`, etc.) are preserved.

  - `level="balanced"` - same attack-vector stripping as `strict`, but
    keeps form interactivity working. Preserved in this mode:
    `/SubmitForm`, `/ResetForm`, and `/JavaScript` annotation actions;
    annotation `/AA` (calculate / format / validate triggers) and `/JS`
    keys; the AcroForm `/CO` calculation order; embedded files (PDF
    portfolios). Use only when you trust the source.
- `scan(path, password=None)` - read-only inspection. Returns a
  `ScanReport` with detected findings and a risk level
  (`none` / `low` / `medium` / `high`).
- Full encrypted PDF support: encryption is **preserved** on save when a
  password is supplied. Wrong-password attempts return a clean error
  report without modifying the input.

### Added — Async API

- `sanitize_async(...)` and `scan_async(...)` - non-blocking versions
  that offload to a thread pool. Drop-in for FastAPI, aiohttp, etc.

### Added — Bytes API

- `sanitize_bytes(data, return_report=False, password=None)` - process
  PDFs entirely in memory. Returns cleaned bytes (or `(bytes, report)`
  tuple when `return_report=True`). Useful for S3 streaming, Lambda,
  and any pipeline that can't afford disk I/O.
- `scan_bytes(data, password=None)` - in-memory scanning.

### Added — CLI

- `pdf-defang clean <files>` - sanitize one or more PDFs
- `pdf-defang scan <file>` - inspect without modification
- Both support `--password`, `--json`, `--quiet`, and follow shell exit
  code conventions (0=success, 1=modifications/findings, 2=error)
- `clean` accepts `--level strict|balanced` (default `strict`)

### Added — Quality

- 133 automated tests covering core sanitizer, scanner, CLI, edge cases,
  URI filtering, encryption preservation, async path, bytes path, the
  extended dangerous-action set, and the strict/balanced level split.
- 90% test coverage.
- Strict `mypy` compliance (`--strict --ignore-missing-imports`).
- `ruff` clean.
- Performance baseline (~0.3-8ms per file on commodity hardware).

### Added — Docs and OSS infrastructure

- Full documentation site at `https://kovetz-PDF.github.io/pdf-defang/`
  (MkDocs Material, auto-deployed via GitHub Actions)
- Examples directory with 5 real-world scripts (Flask, FastAPI, batch
  processor, audit-only, S3 streaming)
- `SECURITY.md` with vulnerability disclosure policy
- `CONTRIBUTING.md` with style guide
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
- GitHub Issue Templates for bug, feature, and security reports
- Dependabot configured for weekly security updates
- Auto-publish to PyPI on git tag (`v*`) via Trusted Publishers (no API
  tokens needed)
- CI matrix testing on Python 3.9-3.13 across Linux, macOS, and Windows

### Dependency policy

- `pikepdf` version range is `>=8.0,<10.0`. We test against the current
  major version and one previous; we explicitly avoid auto-upgrading to
  yet-to-be-released major versions (e.g., pikepdf 10.0 when it ships)
  until we've verified compatibility. This protects users from silent
  breakage when an upstream major release changes the API.

### Field-tested

- Validated against 4,558 real-world PDFs (1.96 GB total) before
  release. Sanitization preserved page count on every successful run.
  No bugs in pdf-defang itself were uncovered; the 18 files that failed
  to process were corrupted PDFs that pikepdf could not open at all.

[0.1.0]: https://github.com/kovetz-PDF/pdf-defang/releases/tag/v0.1.0
