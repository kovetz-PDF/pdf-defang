# Known limitations

`pdf-defang` strips active content. It does not solve every PDF threat.
Honest documentation of what we don't cover:

## Out of scope

### Visual phishing

A PDF can display a convincing fake login page using just text and
images, with no active content. We don't analyse visible content.

**Mitigation:** Email gateway content analysis, user awareness training.

### Type 3 fonts with PostScript

Type 3 fonts embed PostScript drawing commands. Historically a CVE
source (2010-2015). We don't strip these because doing so would break
the rendering of legitimate PDFs that use them.

**Mitigation:** Re-image the PDF using a tool like
[Dangerzone](https://dangerzone.rocks/) for high-risk inputs.

### Parser vulnerabilities in pikepdf / qpdf

A bug in our PDF parser could be triggered by a malformed PDF before our
sanitization runs.

**Mitigation:** Keep `pikepdf` updated. Sandbox PDF processing.

### Social engineering

A PDF doesn't need active content to be dangerous - it can ask the user
to click a button that submits credentials to an attacker URL. In
`level="strict"` we strip `SubmitForm` actions; in `level="balanced"`
they are intentionally preserved (for legitimate form submission), so
balanced offers no protection against this vector. Either way, a button
that's actually a plain link to an external phishing page still works.

**Mitigation:** User awareness. Layer with URL reputation services.

### Steganography / hidden data

A PDF can carry hidden information in images (steganography), metadata,
or whitespace. We don't analyse for this.

**Mitigation:** Use a dedicated steganalysis tool if this matters for
your threat model.

## Defense in depth

`pdf-defang` is one layer. For high-risk workflows (executive email,
legal document intake, government file exchange), combine with:

1. **AV / EDR scanning** - signatures catch known malware families
2. **Sandboxed processing** - run pikepdf/our library in a container or
   subprocess with limited filesystem and network access
3. **Email gateway filtering** - content-aware filters at the perimeter
4. **User awareness** - phishing resistance training
5. **Re-imaging for highest-risk inputs** -
   [Dangerzone](https://dangerzone.rocks/) renders PDFs to images and
   reassembles, defeating most active-content threats at the cost of
   throughput
