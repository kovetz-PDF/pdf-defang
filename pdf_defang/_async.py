"""
Async wrappers for sanitize() and scan().

These offload the synchronous pikepdf calls to a thread pool, so they're
non-blocking in asyncio event loops (FastAPI, aiohttp, Starlette, etc.).

The underlying PDF processing is CPU-bound (and pikepdf releases the GIL
for some operations), so using ``asyncio.to_thread`` is the appropriate
pattern.

Example::

    from fastapi import FastAPI, UploadFile
    from pdf_defang import sanitize_async

    app = FastAPI()

    @app.post("/upload")
    async def upload(file: UploadFile):
        contents = await file.read()
        # write to temp file, then sanitize without blocking the event loop
        ...
        await sanitize_async("/tmp/uploaded.pdf")
"""
from __future__ import annotations

import asyncio
import os
from typing import Literal, overload

from ._core import Level, SanitizeReport, sanitize
from ._scan import ScanReport, scan


@overload
async def sanitize_async(
    pdf_path: str | os.PathLike[str],
    *,
    return_report: Literal[False] = False,
    password: str | None = None,
    level: Level = "strict",
) -> bool: ...


@overload
async def sanitize_async(
    pdf_path: str | os.PathLike[str],
    *,
    return_report: Literal[True],
    password: str | None = None,
    level: Level = "strict",
) -> SanitizeReport: ...


async def sanitize_async(
    pdf_path: str | os.PathLike[str],
    *,
    return_report: bool = False,
    password: str | None = None,
    level: Level = "strict",
) -> bool | SanitizeReport:
    """
    Async version of :func:`pdf_defang.sanitize`.

    Same arguments and return semantics; runs the underlying call in a
    thread so it doesn't block the asyncio event loop.

    Use this in FastAPI, aiohttp, Starlette or any other asyncio web
    framework where you don't want PDF processing to stall request
    handling.
    """
    if return_report:
        return await asyncio.to_thread(
            sanitize, pdf_path, return_report=True, password=password, level=level,
        )
    return await asyncio.to_thread(
        sanitize, pdf_path, return_report=False, password=password, level=level,
    )


async def scan_async(
    pdf_path: str | os.PathLike[str],
    *,
    password: str | None = None,
) -> ScanReport:
    """
    Async version of :func:`pdf_defang.scan`.

    Same arguments and return; offloaded to a thread.
    """
    return await asyncio.to_thread(scan, pdf_path, password=password)
