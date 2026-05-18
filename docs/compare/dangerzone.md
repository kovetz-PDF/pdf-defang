# vs Dangerzone

[Dangerzone](https://dangerzone.rocks/) is an excellent free tool. It
solves a different problem than `pdf-defang`.

## The difference

|  | Dangerzone | pdf-defang |
|---|---|---|
| **Approach** | Render PDF to images, reassemble | Strip dangerous structures from existing PDF |
| **Output** | Visually identical, but flattened to images | Original PDF, with active content removed |
| **Searchable text** | Lost (becomes images), or OCR'd back imperfectly | Preserved |
| **Form fields** | Lost | Preserved |
| **Bookmarks / TOC** | Lost | Preserved |
| **Per-file time** | Minutes (container + render + OCR) | Milliseconds |
| **Setup** | Docker required, ~1GB image | `pip install`, ~250KB |
| **CPU/RAM** | Significant (full container + Tesseract) | Minimal |
| **GUI** | Yes | No (CLI + library) |
| **Library API** | No (CLI/GUI only) | Yes (Python) |

## When to use Dangerzone

Use Dangerzone when:

- The PDF source is **highly untrusted** (random email attachments, leaks)
- You can tolerate visible content becoming images
- You don't need to preserve form interactivity
- Per-file processing time isn't critical
- You want defense against parser-level vulnerabilities too

## When to use pdf-defang

Use pdf-defang when:

- You operate a service that processes user-uploaded PDFs (web app, SaaS)
- You need to **preserve visible content** (text searchability, forms)
- You're handling thousands of files per day - throughput matters
- You're integrating into a Python codebase (Flask, FastAPI, etc.)
- The threat model is "users uploading PDFs without realising they
  contain active content" rather than "nation-state APT delivering a
  targeted exploit"

## Use both?

You can. Pattern:

1. Run `pdf-defang scan` cheaply on every file
2. For files where `risk_level == "high"`, route to Dangerzone for full
   re-imaging
3. For others, `pdf-defang sanitize` and ship

This gets you near-zero latency on the 99% of files that are mostly fine
and full-paranoia treatment on the 1% that look suspicious.
