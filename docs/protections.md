# What gets removed

Complete reference of every dangerous element `pdf-defang` strips, and
how each level treats it.

## Levels at a glance

`sanitize()` accepts a `level` keyword:

| `level` | Form interactivity | Embedded files | Default |
|---|---|---|---|
| `"strict"` | stripped | stripped | yes |
| `"balanced"` | preserved | preserved | no |

Both levels strip pure attack vectors. `balanced` differs only in
**what it leaves alone** so legitimate forms and PDF portfolios survive.

## Document-level

| Element | Path | What it does | Risk | `strict` | `balanced` |
|---|---|---|---|---|---|
| Document JavaScript | `/Catalog → /Names → /JavaScript` | Runs JS automatically when the PDF opens (in vulnerable viewers) | 🔴 High | removed | removed |
| Embedded files | `/Catalog → /Names → /EmbeddedFiles` | Hides files (often malware) inside the PDF container | 🟡 Medium | removed | **kept** |
| Open action | `/Catalog → /OpenAction` | Auto-executes an action when the PDF opens | 🔴 High | removed | removed |
| Document `/AA` | `/Catalog → /AA` | Auto-executes on navigation events (close, print, etc.) | 🔴 High | removed | removed |
| XFA forms | `/Catalog → /AcroForm → /XFA` | Legacy XML-based forms - long history of CVEs | 🔴 High | removed | removed |
| Calculation order | `/Catalog → /AcroForm → /CO` | Form field calculation order (can trigger JS chains) | 🟡 Medium | removed | **kept** |

## Page-level

| Element | Path | What it does | Risk | `strict` | `balanced` |
|---|---|---|---|---|---|
| Page `/AA` | Each page's `/AA` | Auto-executes on page-level events (open, close) | 🟡 Medium | removed | removed |

## Annotation-level

### Action types

| Action `/S` value | What it does | Risk | `strict` | `balanced` |
|---|---|---|---|---|
| `/JavaScript` | Runs JS when the user clicks the annotation | 🔴 High | removed | **kept** (form calculations) |
| `/Launch` | Opens an external program (e.g., `calc.exe`) | 🔴 High | removed | removed |
| `/ImportData` | Reads external data into form fields | 🔴 High | removed | removed |
| `/SubmitForm` | Sends form values to a URL | 🟡 Medium | removed | **kept** |
| `/ResetForm` | Clears the form | 🟡 Medium | removed | **kept** |
| `/Rendition` | Plays media - legacy attack surface | 🟡 Medium | removed | removed |
| `/GoToR` | Opens another PDF (`file://` or `http://` - phishing vector) | 🔴 High | removed | removed |
| `/GoToE` | Opens an embedded file | 🟡 Medium | removed | removed |
| `/Movie` | Deprecated movie playback - old reader exploits | 🟢 Low (deprecated) | removed | removed |
| `/Sound` | Deprecated sound playback - same | 🟢 Low (deprecated) | removed | removed |

### URI scheme filtering (both levels)

`/URI` actions are **not** removed (legitimate hyperlinks).
But the URL value is checked: if the scheme is dangerous, the action is
stripped. This filtering is identical in `strict` and `balanced`.

| Scheme | Action |
|---|---|
| `http://`, `https://`, `mailto:`, `tel:`, `ftp://`, `sftp://`, `news:`, `nntp:`, `irc://`, `magnet:` | ✅ Kept |
| `javascript:` | ❌ Removed |
| `file://` | ❌ Removed (local file access) |
| `data:` | ❌ Removed (data URIs, can carry HTML) |
| `vbscript:` | ❌ Removed |
| `\\server\share` (Windows UNC paths) | ❌ Removed |
| `//server/share` (alternate UNC form) | ❌ Removed |
| Any other unknown scheme | ❌ Removed (whitelist approach) |
| Relative URIs (no scheme) | ✅ Kept (usually in-document) |

### Annotation-level extras

| Element | What it does | `strict` | `balanced` |
|---|---|---|---|
| `/AA` on annotation | Auto-actions when hovering / focusing / calculating | removed | **kept** (form triggers) |
| `/JS` on annotation | Direct JavaScript attached to annotation | removed | **kept** (form calculations) |

## What is preserved (both levels)

`pdf-defang` is **non-destructive to visible content**:

- All text, images, and layout
- Standard form fields (filled values stay intact)
- Bookmarks, table of contents, page labels
- Document metadata (Author, Title, Subject, Keywords)
- Standard link annotations to `mailto:` / `http(s):` URLs
- Document structure, page count, page order
- **Encryption** (when password provided)

A PDF passing through `pdf-defang` looks identical to a human reader,
just without the executable surface.

## When to pick which level

- **`strict`** - the default. Use when accepting PDFs from anyone you
  don't know: public upload forms, email attachments, customer file
  shares. Form interactivity is sacrificed for safety, but every viewer
  still displays the document content normally.
- **`balanced`** - opt in only when forms must actually work end-to-end
  (calculator buttons, "Submit" buttons, format/validate triggers) and
  you've vetted the source. Tax returns, expense reports, and similar
  internal documents are typical examples.
