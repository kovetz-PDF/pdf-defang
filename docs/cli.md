# CLI Reference

The `pdf-defang` command-line tool is installed automatically with the
package.

```bash
pdf-defang --help
```

## Commands

### `pdf-defang clean <files...>`

Sanitize one or more PDFs in place.

```bash
pdf-defang clean uploaded.pdf
pdf-defang clean *.pdf
pdf-defang clean --quiet --json *.pdf > audit.json
pdf-defang clean --password hunter2 encrypted.pdf
pdf-defang clean --level balanced internal_form.pdf
```

**Options:**

| Option | Description |
|---|---|
| `--password`, `-p` | Password for encrypted PDFs (applied to all files) |
| `--level`, `-l` | `strict` (default) or `balanced`. `balanced` preserves form interactivity and embedded files - see [Protections](protections.md) |
| `--json`, `-j` | Output detailed report as JSON instead of human text |
| `--quiet`, `-q` | Suppress per-file output. Exit code still reflects outcome |

**Exit codes:**

- `0` - All files were already clean
- `1` - At least one file had something stripped (informational)
- `2` - At least one file failed to open or process

This means you can chain it::

    pdf-defang clean *.pdf && echo "All clean!" || echo "Some files were modified or failed"

### `pdf-defang scan <file>`

Inspect a single PDF and report findings without modification.

```bash
pdf-defang scan suspicious.pdf
pdf-defang scan suspicious.pdf --json
pdf-defang scan encrypted.pdf --password hunter2
```

**Options:**

| Option | Description |
|---|---|
| `--password`, `-p` | Password for encrypted PDF |
| `--json`, `-j` | Output report as JSON |

**Exit codes:**

- `0` - No active content detected (`risk_level=none`)
- `1` - Active content detected (`low`/`medium`/`high`)
- `2` - Could not scan (encrypted without password, malformed, etc.)

### `pdf-defang --version`

Print the installed version.

## Examples

### Pipe to logging

```bash
pdf-defang clean uploads/*.pdf --json | jq -c 'map({file, modified, error})' > audit.jsonl
```

### Quarantine high-risk files

```bash
for f in incoming/*.pdf; do
    if pdf-defang scan "$f" --json | jq -e '.risk_level == "high"' > /dev/null; then
        mv "$f" quarantine/
    fi
done
```

### Use as a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pdf-defang
        name: Sanitize PDFs
        entry: pdf-defang clean
        language: system
        files: \.pdf$
```
