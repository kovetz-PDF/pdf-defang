"""
One-shot script to generate test fixture PDFs.

Run once from the repo root::

    python tests/fixtures/generate_fixtures.py

Produces:
  - clean.pdf       - 2 pages, no active content
  - with_js.pdf     - has document-level /JavaScript in /Names
  - with_openaction.pdf - has /OpenAction
  - with_embedded.pdf   - has /EmbeddedFiles
  - with_launch_annot.pdf - has a Launch action on an annotation
  - with_everything.pdf - kitchen sink
"""
from __future__ import annotations

from pathlib import Path
import pikepdf
from pikepdf import Dictionary, Name, String, Array

HERE = Path(__file__).resolve().parent


def _new_pdf(num_pages: int = 2) -> pikepdf.Pdf:
    pdf = pikepdf.Pdf.new()
    for _ in range(num_pages):
        pdf.add_blank_page(page_size=(612, 792))
    return pdf


def _save(pdf: pikepdf.Pdf, name: str) -> None:
    path = HERE / name
    pdf.save(path)
    pdf.close()
    print(f"  wrote {path.name} ({path.stat().st_size:,} bytes)")


def make_clean() -> None:
    pdf = _new_pdf(2)
    _save(pdf, "clean.pdf")


def make_with_js() -> None:
    pdf = _new_pdf(2)
    js_action = pdf.make_indirect(Dictionary(
        S=Name("/JavaScript"),
        JS=String("app.alert('hello');"),
    ))
    pdf.Root.Names = Dictionary(
        JavaScript=Dictionary(
            Names=Array([String("OnLoad"), js_action]),
        ),
    )
    _save(pdf, "with_js.pdf")


def make_with_openaction() -> None:
    pdf = _new_pdf(2)
    pdf.Root.OpenAction = Dictionary(
        S=Name("/JavaScript"),
        JS=String("app.alert('opened');"),
    )
    _save(pdf, "with_openaction.pdf")


def make_with_embedded() -> None:
    pdf = _new_pdf(2)
    file_spec = pdf.make_indirect(Dictionary(
        Type=Name("/Filespec"),
        F=String("note.txt"),
        EF=Dictionary(
            F=pdf.make_stream(b"This is an embedded file.", Type=Name("/EmbeddedFile")),
        ),
    ))
    pdf.Root.Names = Dictionary(
        EmbeddedFiles=Dictionary(
            Names=Array([String("note.txt"), file_spec]),
        ),
    )
    _save(pdf, "with_embedded.pdf")


def make_with_launch_annot() -> None:
    pdf = _new_pdf(2)
    page = pdf.pages[0]
    annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([100, 100, 200, 120]),
        A=Dictionary(
            S=Name("/Launch"),
            F=String("calc.exe"),
        ),
    ))
    page.Annots = Array([annot])
    _save(pdf, "with_launch_annot.pdf")


def make_with_dangerous_uri() -> None:
    """PDF with annotations containing javascript:, file:, and UNC URIs."""
    pdf = _new_pdf(2)
    page = pdf.pages[0]
    # Three annotations: javascript:, file://, and a SAFE https URL (control)
    js_uri_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([50, 50, 200, 70]),
        A=Dictionary(
            S=Name("/URI"),
            URI=String("javascript:alert('xss')"),
        ),
    ))
    file_uri_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([50, 80, 200, 100]),
        A=Dictionary(
            S=Name("/URI"),
            URI=String("file:///C:/Windows/System32/calc.exe"),
        ),
    ))
    unc_uri_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([50, 110, 200, 130]),
        A=Dictionary(
            S=Name("/URI"),
            URI=String("\\\\attacker.com\\share\\malware.exe"),
        ),
    ))
    safe_uri_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([50, 140, 200, 160]),
        A=Dictionary(
            S=Name("/URI"),
            URI=String("https://example.com/safe"),
        ),
    ))
    page.Annots = Array([js_uri_annot, file_uri_annot, unc_uri_annot, safe_uri_annot])
    _save(pdf, "with_dangerous_uris.pdf")


def make_with_gotor() -> None:
    """PDF with a /GoToR action (opens external PDF) - now considered dangerous."""
    pdf = _new_pdf(2)
    page = pdf.pages[0]
    gotor_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([100, 100, 200, 120]),
        A=Dictionary(
            S=Name("/GoToR"),
            F=String("\\\\attacker.com\\share\\evil.pdf"),
        ),
    ))
    page.Annots = Array([gotor_annot])
    _save(pdf, "with_gotor.pdf")


def make_with_movie_sound() -> None:
    """PDF with deprecated /Movie and /Sound annotation actions."""
    pdf = _new_pdf(2)
    page = pdf.pages[0]
    movie_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([50, 50, 200, 70]),
        A=Dictionary(
            S=Name("/Movie"),
            T=String("movie title"),
        ),
    ))
    sound_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([50, 80, 200, 100]),
        A=Dictionary(
            S=Name("/Sound"),
        ),
    ))
    page.Annots = Array([movie_annot, sound_annot])
    _save(pdf, "with_movie_sound.pdf")


def make_encrypted_with_js(password: str = "secret123") -> None:
    """Encrypted PDF (AES-128) that ALSO has dangerous JavaScript inside.

    Used to verify that sanitization preserves encryption.
    """
    pdf = _new_pdf(2)
    js_action = pdf.make_indirect(Dictionary(
        S=Name("/JavaScript"),
        JS=String("app.alert('hidden inside encrypted');"),
    ))
    pdf.Root.Names = Dictionary(
        JavaScript=Dictionary(
            Names=Array([String("OnLoad"), js_action]),
        ),
    )
    pdf.Root.OpenAction = Dictionary(S=Name("/JavaScript"), JS=String("x();"))

    encryption = pikepdf.Encryption(owner=password, user=password, R=4)
    path = HERE / "encrypted_with_js.pdf"
    pdf.save(path, encryption=encryption)
    pdf.close()
    print(f"  wrote {path.name} ({path.stat().st_size:,} bytes) [encrypted, password={password}]")


def make_with_form_actions() -> None:
    """PDF carrying the *form* family of actions: SubmitForm, ResetForm,
    annotation JavaScript, annotation /AA, annotation /JS, and AcroForm /CO.

    These items are removed in ``strict`` mode but preserved in ``balanced``
    mode, so this fixture exercises both code paths.
    """
    pdf = _new_pdf(2)
    page = pdf.pages[0]

    submit_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Widget"),
        Rect=Array([100, 100, 200, 120]),
        A=Dictionary(S=Name("/SubmitForm"), F=String("https://example.com/post")),
    ))
    reset_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Widget"),
        Rect=Array([100, 130, 200, 150]),
        A=Dictionary(S=Name("/ResetForm")),
    ))
    js_button_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Widget"),
        Rect=Array([100, 160, 200, 180]),
        A=Dictionary(
            S=Name("/JavaScript"),
            JS=String("this.getField('total').value = a + b;"),
        ),
    ))
    # Annotation with /AA (form calculate/format triggers) and /JS keys
    aa_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Widget"),
        Rect=Array([100, 190, 200, 210]),
        AA=Dictionary(
            C=Dictionary(
                S=Name("/JavaScript"),
                JS=String("event.value = this.getField('a').value * 1.17;"),
            ),
        ),
        JS=String("this.getField('inline').value = 'computed';"),
    ))

    # Embedded file (used by PDF portfolios)
    file_spec = pdf.make_indirect(Dictionary(
        Type=Name("/Filespec"),
        F=String("attachment.txt"),
        EF=Dictionary(
            F=pdf.make_stream(b"portfolio attachment", Type=Name("/EmbeddedFile")),
        ),
    ))
    pdf.Root.Names = Dictionary(
        EmbeddedFiles=Dictionary(
            Names=Array([String("attachment.txt"), file_spec]),
        ),
    )

    # AcroForm with /CO and Fields
    pdf.Root.AcroForm = Dictionary(
        Fields=Array([submit_annot, reset_annot, js_button_annot, aa_annot]),
        CO=Array([aa_annot]),
    )

    page.Annots = Array([submit_annot, reset_annot, js_button_annot, aa_annot])
    _save(pdf, "with_form_actions.pdf")


def make_with_everything() -> None:
    pdf = _new_pdf(3)

    # Document JS
    js_action = pdf.make_indirect(Dictionary(
        S=Name("/JavaScript"),
        JS=String("app.alert('x');"),
    ))

    # Embedded file
    file_spec = pdf.make_indirect(Dictionary(
        Type=Name("/Filespec"),
        F=String("note.txt"),
        EF=Dictionary(
            F=pdf.make_stream(b"embedded", Type=Name("/EmbeddedFile")),
        ),
    ))

    pdf.Root.Names = Dictionary(
        JavaScript=Dictionary(
            Names=Array([String("OnLoad"), js_action]),
        ),
        EmbeddedFiles=Dictionary(
            Names=Array([String("note.txt"), file_spec]),
        ),
    )
    pdf.Root.OpenAction = Dictionary(S=Name("/JavaScript"), JS=String("x();"))
    pdf.Root.AA = Dictionary(O=Dictionary(S=Name("/JavaScript"), JS=String("x();")))

    # Page-level AA
    pdf.pages[0].AA = Dictionary(O=Dictionary(S=Name("/JavaScript"), JS=String("x();")))

    # Launch annotation on page 1
    launch_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([100, 100, 200, 120]),
        A=Dictionary(S=Name("/Launch"), F=String("calc.exe")),
    ))
    # JS annotation on page 2
    js_annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"),
        Subtype=Name("/Link"),
        Rect=Array([100, 100, 200, 120]),
        A=Dictionary(S=Name("/JavaScript"), JS=String("alert(1)")),
    ))
    pdf.pages[0].Annots = Array([launch_annot])
    pdf.pages[1].Annots = Array([js_annot])

    _save(pdf, "with_everything.pdf")


def main() -> None:
    print("Generating test fixtures...")
    make_clean()
    make_with_js()
    make_with_openaction()
    make_with_embedded()
    make_with_launch_annot()
    make_with_dangerous_uri()
    make_with_gotor()
    make_with_movie_sound()
    make_with_form_actions()
    make_with_everything()
    make_encrypted_with_js()
    print("Done.")


if __name__ == "__main__":
    main()
