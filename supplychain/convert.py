"""Stage 3 — convert pickle weights to safetensors.

Scanning is detection; conversion is *elimination*. safetensors is a flat,
non-executable format: a JSON header plus raw tensor bytes, with no opcode
stream and therefore no code-execution surface at load time. Once converted,
the whole class of deserialization attacks is structurally gone rather than
merely not-detected.

The conversion is only trustworthy if it is faithful, so every tensor is
compared byte-for-byte against the original before the pickle is dropped.
"""

from __future__ import annotations

import pathlib
import shutil
from typing import Any

import torch
from safetensors.torch import load_file as load_safetensors
from safetensors.torch import save_file

from .config import Settings
from .ingest import staged_root
from .report import hash_manifest, read_report, stage, write_report

PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt"}
# Copied through untouched: config, tokenizer, model card.
METADATA_SUFFIXES = {".json", ".txt", ".md", ".model"}


def _load_checkpoint(path: pathlib.Path) -> dict[str, torch.Tensor]:
    # weights_only=True refuses to execute arbitrary reduce ops during *our* load.
    # The scan already gated this file; this is defence in depth for the one
    # moment the pipeline is obliged to open an untrusted pickle.
    state = torch.load(path, map_location="cpu", weights_only=True)
    if not isinstance(state, dict):
        raise TypeError(f"{path.name}: expected a state dict, got {type(state).__name__}")
    return {k: v for k, v in state.items() if isinstance(v, torch.Tensor)}


def _verify_equivalence(
    original: dict[str, torch.Tensor], converted_path: pathlib.Path
) -> None:
    roundtrip = load_safetensors(str(converted_path))
    if set(roundtrip) != set(original):
        missing = set(original) ^ set(roundtrip)
        raise ValueError(f"tensor set changed during conversion: {sorted(missing)}")
    for name, tensor in original.items():
        if not torch.equal(tensor, roundtrip[name]):
            raise ValueError(f"tensor '{name}' differs after conversion")


def run(cfg: Settings) -> dict[str, Any]:
    scan_report = read_report(cfg.reports_dir / "scan.json")
    if scan_report["verdict"] != "PASS":
        raise RuntimeError("scan verdict is FAIL — refusing to convert a flagged model")

    root = staged_root(cfg)
    out = cfg.secured_dir
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    converted: list[dict[str, Any]] = []
    passthrough: list[str] = []

    for src in sorted(root.rglob("*")):
        if not src.is_file() or ".cache" in src.parts:
            continue
        rel = src.relative_to(root)
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)

        if src.suffix in PICKLE_SUFFIXES:
            tensors = _load_checkpoint(src)
            target = dst.with_suffix(".safetensors")
            # contiguous() because safetensors rejects non-contiguous views,
            # which shared-storage checkpoints routinely contain.
            save_file({k: v.contiguous() for k, v in tensors.items()}, str(target))
            _verify_equivalence(tensors, target)
            converted.append(
                {"from": str(rel), "to": str(target.relative_to(out)), "tensors": len(tensors)}
            )
            stage("convert", f"{rel} → {target.name} ({len(tensors)} tensors verified)")
        elif src.suffix in METADATA_SUFFIXES or src.suffix == ".safetensors":
            shutil.copy2(src, dst)
            passthrough.append(str(rel))
        else:
            stage("convert", f"dropping unrecognised file {rel}", "info")

    if not any(p.suffix == ".safetensors" for p in out.rglob("*")):
        raise RuntimeError("no safetensors weights produced — nothing to sign")

    report = {
        "converted": converted,
        "passthrough": passthrough,
        "secured_dir": str(out),
        "hashes": hash_manifest(out),
    }
    write_report(cfg.reports_dir / "convert.json", report)
    stage("convert", f"{len(converted)} converted, {len(passthrough)} copied", "ok")
    return report
