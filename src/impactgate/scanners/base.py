"""Scanner protocol and subprocess runner."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from impactgate.models import Finding

LOGGER = logging.getLogger("impactgate.scanners")
SCANNER_TIMEOUT_SECONDS = 30


def with_guidance(evidence: str, *parts: object) -> str:
    """Append scanner-provided remediation text to evidence. Skip blanks and duplicates."""
    extras: list[str] = []
    for part in parts:
        if not isinstance(part, str):
            continue
        text = part.strip()
        if not text or text in evidence or text in extras:
            continue
        extras.append(text)
    if not extras:
        return evidence
    return f"{evidence}. {' '.join(extras)}"


class Scanner(Protocol):
    name: str

    async def scan(self, files: Sequence[Path]) -> list[Finding]:
        """Run this scanner against ``files``. Never raise to the caller."""
        ...


async def run_command(binary: str, args: Sequence[str]) -> str | None:
    """Run ``binary`` with a hard timeout. Missing binaries and timeouts skip."""
    try:
        process = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        LOGGER.warning("%s is not installed; skipping", binary)
        return None
    except OSError as exc:
        LOGGER.warning("failed to start %s: %s", binary, exc)
        return None
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=SCANNER_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        LOGGER.warning("%s timed out after %ss; skipping", binary, SCANNER_TIMEOUT_SECONDS)
        return None
    if stderr:
        LOGGER.debug("%s stderr: %s", binary, stderr.decode("utf-8", errors="replace"))
    return stdout.decode("utf-8", errors="replace")
