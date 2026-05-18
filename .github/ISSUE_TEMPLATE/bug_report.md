---
name: Bug report
about: A PDF wasn't sanitized correctly, or pdf-defang crashed
title: '[BUG] '
labels: bug
assignees: ''
---

**What happened?**

A clear description of what went wrong.

**What did you expect?**

What you thought should happen.

**Reproducer**

If possible, attach a PDF that demonstrates the issue (or a minimal
reproducer that creates one). Use [GitHub's file upload](https://docs.github.com/en/issues/tracking-your-work-with-issues/file-attachments-on-issues-and-pull-requests)
to attach the file.

If the PDF contains sensitive content, **please do NOT attach it
publicly** - email it to contact@kovetz.co.il instead.

**Steps to reproduce**

```python
from pdf_defang import sanitize

sanitize("bad.pdf")
# what happens?
```

Or via CLI:

```bash
pdf-defang clean bad.pdf
# output here
```

**Environment**

- pdf-defang version: `pip show pdf-defang | grep Version`
- pikepdf version: `pip show pikepdf | grep Version`
- Python version: `python --version`
- OS: (Linux / macOS / Windows)

**Additional context**

Logs, screenshots, output of `pdf-defang scan bad.pdf --json`, anything
else that would help us understand.
