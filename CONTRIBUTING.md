# Contributing to pdf-defang

Thanks for taking the time to contribute! This project is small and
focused, which makes it easy to contribute meaningfully even with a
small change.

## Quick links

- [Issues](https://github.com/kovetz-PDF/pdf-defang/issues) - bug reports and feature requests
- [Security](https://github.com/kovetz-PDF/pdf-defang/blob/main/SECURITY.md) - **for security vulnerabilities, please do NOT open a public issue**
- [Changelog](https://github.com/kovetz-PDF/pdf-defang/blob/main/CHANGELOG.md) - what's changed
- Email: [contact@kovetz.co.il](mailto:contact@kovetz.co.il)

## Ways to help

### Reporting bugs

If you've found a PDF that contains active content `pdf-defang` doesn't
strip, that's a high-priority bug for us. Please open a GitHub issue with:

1. A description of what's wrong
2. The actual PDF file (or a minimal reproducer that demonstrates the issue)
3. The output of `pdf-defang scan <file> --json` on that file
4. The version of `pdf-defang` and `pikepdf` (`pip show pdf-defang pikepdf`)

If the PDF contains sensitive content, see [SECURITY.md](https://github.com/kovetz-PDF/pdf-defang/blob/main/SECURITY.md)
for how to share it privately.

### Suggesting features

Open a GitHub issue with the use case. We're particularly interested in:

- PDF action types we don't currently strip
- Edge cases in URI scheme detection
- Patterns common in PDF malware that we miss
- Integration suggestions (logging frameworks, web frameworks, etc.)

What we'd push back on:

- Visual content analysis (rendering PDFs, looking at images) - out of scope
- Anything that requires a heavy dependency (numpy, machine learning, etc.)
- Plugins/extension points without a clear use case

### Code contributions

#### Setup

```bash
git clone https://github.com/kovetz-PDF/pdf-defang.git
cd pdf-defang
python -m pip install -e ".[test]"
python -m pytest
```

The test suite auto-generates fixture PDFs on first run, so the first
`pytest` invocation is slower than subsequent ones.

#### Style

We use:

- **`ruff`** for lint and formatting: `python -m ruff check pdf_defang/ tests/`
- **`mypy --strict`** for type checking: `python -m mypy pdf_defang/ --strict --ignore-missing-imports`
- **`pytest`** for tests (with `pytest-cov` for coverage)

All three must pass before merging. CI will check.

#### Adding a new dangerous content type

The most common contribution is "we should also strip X". Steps:

1. Add the action/key to the appropriate constant in
   [`pdf_defang/_core.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/pdf_defang/_core.py)
   (e.g., `_DANGEROUS_ACTION_TYPES`)
2. Update the matching detection in
   [`pdf_defang/_scan.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/pdf_defang/_scan.py)
3. Create a fixture PDF in
   [`tests/fixtures/generate_fixtures.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/tests/fixtures/generate_fixtures.py)
   that contains the new threat
4. Add tests in `tests/test_sanitize.py` and `tests/test_scan.py` that
   verify both detection and removal
5. Update the relevant section of
   [README.md](https://github.com/kovetz-PDF/pdf-defang/blob/main/README.md)
6. Add an entry under "Unreleased" in
   [CHANGELOG.md](https://github.com/kovetz-PDF/pdf-defang/blob/main/CHANGELOG.md)

#### Pull request checklist

- [ ] Tests pass (`python -m pytest`)
- [ ] Lint passes (`python -m ruff check`)
- [ ] Types pass (`python -m mypy --strict`)
- [ ] Coverage doesn't drop below 85%
- [ ] README updated if the public API changed
- [ ] CHANGELOG entry added

## Code of Conduct

Be kind. We're all here to make the Python ecosystem a little safer.
See [CODE_OF_CONDUCT.md](https://github.com/kovetz-PDF/pdf-defang/blob/main/CODE_OF_CONDUCT.md)
for the formal version (Contributor Covenant).
