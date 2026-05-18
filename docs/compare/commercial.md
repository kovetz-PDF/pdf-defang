# vs commercial PDF SDKs

Commercial PDF SDKs like [iText](https://itextpdf.com/),
[Apryse / PDFTron](https://apryse.com/), and
[Foxit PDF SDK](https://www.foxit.com/pdf-sdk/) are powerful, mature
products. They are also expensive and closed-source.

## When commercial SDKs make sense

- Enterprise deployments where you need full PDF spec coverage (forms,
  digital signatures, advanced rendering, OCR, etc.)
- Industries with strict regulatory compliance and need vendor support
- Workflows where the SDK is one piece of a much larger PDF pipeline
- Budgets that absorb $3,000-$20,000+/year licensing

## When pdf-defang fits instead

- Solo developers and small teams without enterprise budget
- Single-purpose pipelines where you just need PDFs stripped of active
  content - not the full PDF kitchen sink
- Open-source projects that need a permissive license
- Government / non-profit / academic where commercial licensing is
  bureaucratically painful

## Detailed comparison

|  | Commercial SDK | pdf-defang |
|---|---|---|
| **License cost** | $3,000-$20,000+/year | Free, MIT |
| **Source code access** | No (proprietary) | Yes (GitHub) |
| **Audit & review** | NDA / closed-box | Public, anyone can review |
| **Sanitization quality** | Excellent (full feature) | Focused, well-defined scope |
| **Encryption support** | Full (AES-256, certificates, etc.) | Preserve existing encryption |
| **Async API** | Varies | Built in |
| **Bytes API** | Varies | Built in |
| **Custom extensions** | Often paid add-ons | Fork & modify freely |
| **Python integration** | Some via wrappers | Native |
| **Dependencies** | Often heavy (DLLs, runtime libs) | Just pikepdf |
| **Vendor support** | Yes, contractual | Community + GitHub issues |

## Hybrid setups

Some teams use both. For instance:

- iText for **signing** PDFs (commercial signing requires certified SDKs
  in some jurisdictions)
- `pdf-defang` for **sanitizing** uploaded PDFs before they enter the
  signing pipeline

This is the right pattern for "regulated industries that also accept
public uploads."
