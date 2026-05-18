# Security Policy

`pdf-defang` is a security library: people use it to protect their
applications from malicious PDFs. We treat vulnerabilities seriously.

## Supported versions

Only the latest minor release is supported. We will issue security fixes
on top of the most recent release, not on older branches.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

If you believe you have found a vulnerability in `pdf-defang`, please email:

> **contact@kovetz.co.il**

Include:

1. A description of the vulnerability and its impact
2. A minimal reproducer (a PDF that demonstrates the issue, or a code snippet)
3. The version of `pdf-defang` and `pikepdf` you tested with
4. Whether the issue has been disclosed elsewhere

We will:

1. Acknowledge receipt within **3 business days**
2. Confirm or refute the issue within **14 days**
3. For confirmed issues, prepare a fix and coordinate disclosure with you
4. Credit you in the changelog and release notes (unless you prefer otherwise)

## What counts as a vulnerability

In scope:

- A PDF that causes `sanitize()` to silently leave dangerous content in the
  output file
- A PDF that causes `scan()` to miss dangerous content it should detect
- A PDF that causes `pdf-defang` to read or write files outside the supplied
  path
- Path traversal, command injection, or arbitrary code execution via library
  inputs

Out of scope:

- A PDF that crashes `pikepdf` (please report to the
  [pikepdf project](https://github.com/pikepdf/pikepdf))
- A PDF whose **visible** content cannot be opened by Adobe Reader after
  sanitization (this is a bug, but not a security issue - please open a regular issue)
- Use of this library as the only line of defense against PDF threats - we
  recommend defense in depth (AV, sandboxing, content disarm pipelines)

## Defense-in-depth context

`pdf-defang` strips *active content* from PDFs. It does not:

- Render PDFs to images (see [Dangerzone](https://dangerzone.rocks/) for that)
- Replace antivirus scanning
- Replace a sandboxed PDF viewer for high-risk attachments
- Prevent password-stealing forms that don't use JavaScript

For high-risk workflows (executive email, legal review of unknown
attachments, etc.), layer this library with at least one other control.

## Known limitations

These threats exist in the PDF specification but `pdf-defang` does **not**
currently handle them. They are documented here so users can make informed
decisions about layering additional controls.

### Type 3 fonts with PostScript content

Type 3 fonts embed PostScript drawing commands that the PDF reader executes
to render each glyph. Historically, this surface has had vulnerabilities
(CVEs from 2010-2015 in Adobe Reader). Stripping or replacing Type 3 fonts
would break the visible content of legitimate PDFs that use them, so we
chose not to handle this at sanitization time.

**Risk assessment:** Low in practice. Modern PDF readers run Type 3 glyph
PostScript in restricted contexts. Last published exploitation chain
predates 2018.

**Mitigation if you need it:** Re-image the PDF (Dangerzone-style) or
filter PDFs by font types at a separate layer.

### Visual phishing content

A PDF can display a convincing fake login page using only text and images,
with no active content. `pdf-defang` does not analyse visible content for
phishing patterns.

**Mitigation:** Train users; layer with content-aware filters at the email
gateway.

### Parser vulnerabilities in pikepdf or downstream readers

`pdf-defang` depends on `pikepdf` (which depends on `qpdf`). A parser bug
in one of these could potentially be triggered by a malformed PDF before
our sanitization logic runs.

**Mitigation:** Keep pikepdf updated. Use a sandboxed worker process for
untrusted inputs. Watch the pikepdf changelog for security fixes.
