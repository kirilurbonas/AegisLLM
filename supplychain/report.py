"""Shared helpers for emitting stage reports and console output.

Every stage writes a JSON report next to the artifacts. The reports are the
evidence trail: they are what a later phase attaches to the OCI artifact and
what an auditor reads.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

from rich.console import Console

console = Console()

STAGE_STYLES = {"ok": "bold green", "fail": "bold red", "info": "bold cyan"}


def stage(name: str, message: str, status: str = "info") -> None:
    console.print(f"[{STAGE_STYLES[status]}]{name:>9}[/] {message}")


def write_report(path: pathlib.Path, payload: dict[str, Any]) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n")
    return path


def read_report(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"missing {path.name} — run the earlier pipeline stage first"
        )
    return json.loads(path.read_text())


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_manifest(root: pathlib.Path) -> dict[str, str]:
    """SHA-256 of every file under `root`, keyed by path relative to it."""
    return {
        str(p.relative_to(root)): sha256_file(p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
