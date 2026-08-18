from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"


def _run(code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC) if not existing else str(SRC) + os.pathsep + existing
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


PACKAGES = (
    "impactgate",
    "impactgate.graph",
    "impactgate.analysis",
    "impactgate.scanners",
    "impactgate.llm",
    "impactgate.cache",
    "impactgate.report",
    "impactgate.github",
    "impactgate.controller",
)


def test_cli_imports_without_circular_import() -> None:
    """Fresh interpreter: importing the CLI must not hit a circular import."""
    result = _run("import impactgate.cli")
    assert result.returncode == 0, result.stderr


def test_import_impactgate_cli() -> None:
    import impactgate.cli as cli

    assert cli.app is not None


def test_package_inits_import_cleanly() -> None:
    """Catch __init__.py cycles that only show up depending on import order."""
    for name in PACKAGES:
        result = _run(f"import {name}")
        assert result.returncode == 0, f"{name}: {result.stderr}"


def test_fingerprint_does_not_load_llm_package() -> None:
    result = _run(
        "import sys, impactgate.cache.fingerprint; "
        "mods = [name for name in sys.modules if name == 'impactgate.llm' "
        "or name.startswith('impactgate.llm.')]; "
        "assert not mods, mods"
    )
    assert result.returncode == 0, result.stderr


def test_cache_package_does_not_load_llm_package() -> None:
    result = _run(
        "import sys, impactgate.cache; "
        "mods = [name for name in sys.modules if name == 'impactgate.llm' "
        "or name.startswith('impactgate.llm.')]; "
        "assert not mods, mods"
    )
    assert result.returncode == 0, result.stderr
