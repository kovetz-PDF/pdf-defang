# Origin story

`pdf-defang` was originally written for [kovetz.co.il](https://kovetz.co.il)
- a Hebrew/English online PDF tools site - in May 2026, in response to a
real security incident.

## The incident

In early May 2026, during a period of regional security escalation, our
Sentry error tracking started showing endpoint probes from
Iranian-attributed IP ranges. The scanner was specifically targeting
upload-handler endpoints, presumably looking for ways to deliver
malicious PDFs.

We had a defensive concern: if an attacker successfully uploaded a
poisoned PDF to our service, and another user later downloaded it
(through one of our processing tools - merge, split, etc.), we'd
effectively be a malware re-emission service. Even if the attacker
couldn't fully compromise our server, they'd compromise our users.

## The fix

Over a single evening (commit `a568483` in the kovetz.co.il monorepo),
we shipped five security hardening fixes:

1. **Ghostscript SAFER mode** for PDF/A conversion paths
2. **Active content stripping** (`sanitize_pdf_active_content`) wired
   into every PDF download path - the function that became this library
3. **Pillow decompression-bomb cap** for image handling
4. **Empty file rejection** in the upload validator
5. **LibreOffice profile isolation** to prevent macro persistence
   across requests

The active-content stripper was 67 lines of pikepdf code. After it had
been running successfully on thousands of files for a few weeks, we
realised:

- There's no clean equivalent in the OSS Python ecosystem.
- The two existing small libraries (`pdf-sanitizer`, `py-pdf-sanitizer`)
  are CLI-only, have 0-1 GitHub stars, and don't handle all the
  dangerous content types.
- The heavyweight option ([Dangerzone](https://dangerzone.rocks/)) needs
  a Docker container and minutes per PDF.

So we extracted our code into this standalone library.

## Who is this actually for?

Being honest about our intended audience matters more than aspirational
positioning. `pdf-defang` is for:

- A solo developer building a Flask or FastAPI app that accepts PDF
  uploads, who needs a defensive layer in three lines of code.
- A small SaaS team without budget for a commercial PDF SDK (which start
  at \$3,000-\$20,000+/year).
- A security researcher cleaning a sample before opening it in a viewer.
- An internal-tools team at a mid-sized company who needs something
  auditable in plain Python rather than a black-box binary.
- A CTF organiser or educator who needs fast, scriptable PDF
  sanitization.

We are **not** trying to displace the products that occupy the upper
end of the market - Adobe's internal stack, Apryse / iText / Foxit
SDKs, regulated-industry tools with certification trails. Those have
decades of engineering, full PDF spec coverage, vendor support
contracts, and certifications we won't match. They're the right choice
for their audience.

What's missing in the OSS Python ecosystem is the **small, focused,
free-as-in-MIT** layer that the long tail of Python developers can drop
in without thinking about it. That's the gap we are filling.

## Why MIT license?

We could have kept it private (a competitive moat). We could have
released it under GPL (forcing forks back).

MIT is the right fit because the audience we're targeting is exactly
the audience that bounces off restrictive licensing. Hobby projects,
small SaaS, internal tools at companies whose legal teams haven't
approved GPL - those need a license they can adopt without a meeting.

## What we kept private

The kovetz.co.il application code itself (Vue/Flask/Hebrew RTL editing,
Israeli payment integration, etc.) is closed source. The OSS pieces are
the focused, reusable utilities like this one. We may release more in
this category over time - the GitHub org [kovetz-PDF](https://github.com/kovetz-PDF)
is the umbrella.
