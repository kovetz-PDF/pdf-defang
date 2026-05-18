"""
pytest fixtures: copy each fixture PDF to a per-test tempdir so tests can
mutate them without affecting the original.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"
EXPECTED_FIXTURES = [
    "clean.pdf",
    "with_js.pdf",
    "with_openaction.pdf",
    "with_embedded.pdf",
    "with_launch_annot.pdf",
    "with_dangerous_uris.pdf",
    "with_gotor.pdf",
    "with_movie_sound.pdf",
    "with_form_actions.pdf",
    "with_everything.pdf",
    "encrypted_with_js.pdf",
]


def _ensure_fixtures_generated() -> None:
    """Auto-generate fixture PDFs if missing (first-run on a fresh clone)."""
    missing = [f for f in EXPECTED_FIXTURES if not (FIXTURE_DIR / f).exists()]
    if not missing:
        return
    script = FIXTURE_DIR / "generate_fixtures.py"
    if not script.exists():
        raise FileNotFoundError(f"Fixture generator not found: {script}")
    subprocess.run([sys.executable, str(script)], check=True)


_ensure_fixtures_generated()


@pytest.fixture
def fixture_pdf(tmp_path: Path):
    """Factory: copy a fixture PDF to tmp_path and return the new path."""
    def _copy(name: str) -> Path:
        src = FIXTURE_DIR / name
        if not src.exists():
            raise FileNotFoundError(f"Fixture {name} not found at {src}")
        dst = tmp_path / name
        shutil.copy(src, dst)
        return dst

    return _copy
