# pdf-defang examples

Real-world usage scripts. Pick the one that matches your use case and
adapt to your stack.

## Examples

| File | Use case |
|---|---|
| [`flask_upload.py`](flask_upload.py) | Flask endpoint that accepts a PDF upload, sanitizes it, and returns the cleaned bytes |
| [`fastapi_async.py`](fastapi_async.py) | FastAPI async endpoint using `sanitize_async` for non-blocking processing |
| [`batch_processor.py`](batch_processor.py) | Walk a directory, sanitize every PDF, write a JSONL audit log |
| [`audit_only.py`](audit_only.py) | Scan PDFs read-only and produce a security report - no modifications |
| [`s3_streaming.py`](s3_streaming.py) | Process PDFs from S3 using `sanitize_bytes` - never touch local disk |

## Running

Each script is standalone and can be run from the repo root:

```bash
# After installing pdf-defang
pip install pdf-defang

# Run an example
python examples/audit_only.py /path/to/pdf_directory
```

Examples that need a web framework note their additional requirements
inline at the top of the file.
