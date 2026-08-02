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

from .config import Settings
from .ingest import staged_root
from .report import hash_manifest, read_report, stage, write_report

PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt"}
# transformers looks for `model.safetensors`; a file named after the pickle it
# came from would load nowhere. Converting to the name the ecosystem expects is
# what makes the secured artifact a drop-in replacement for the original.
CANONICAL_WEIGHTS = {"pytorch_model": "model"}
# Copied through untouched: config, tokenizer, model card.
METADATA_SUFFIXES = {".json", ".txt", ".md", ".model"}


def _safetensors_name(rel: pathlib.Path) -> pathlib.Path:
    stem = CANONICAL_WEIGHTS.get(rel.stem, rel.stem)
    return rel.with_name(f"{stem}.safetensors")


def _torch():
    """Import torch on demand.

    Conversion needs torch; *verification* does not. The verifier runs as an init
    container on every model-serving pod, so keeping torch off its import path is
    the difference between a ~200 MB image and a ~2.5 GB one — and a smaller
    image is also a smaller attack surface on the security-critical component.
    """
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise RuntimeError(
            "conversion requires torch — install with `uv sync --extra convert`"
        ) from exc
    return torch


def _load_checkpoint(path: pathlib.Path) -> dict[str, Any]:
    torch = _torch()
    # weights_only=True refuses to execute arbitrary reduce ops during *our* load.
    # The scan already gated this file; this is defence in depth for the one
    # moment the pipeline is obliged to open an untrusted pickle.
    state = torch.load(path, map_location="cpu", weights_only=True)
    if not isinstance(state, dict):
        raise TypeError(f"{path.name}: expected a state dict, got {type(state).__name__}")
    return {k: v for k, v in state.items() if isinstance(v, torch.Tensor)}


def _materialise_shared_tensors(state: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Give every tensor its own storage.

    Many architectures tie weights — GPT-2 points `lm_head.weight` at
    `transformer.wte.weight`, sharing one buffer. safetensors is a flat mapping of
    name to bytes with no way to express aliasing, so it refuses to save these.

    The two ways out are to drop the duplicates and rely on the loader re-tying
    them, or to clone so each name owns its bytes. This pipeline clones.
    Dropping tensors makes the artifact depend on a loader faithfully
    reconstructing what was removed, which is an assumption the signature cannot
    cover: the bytes we sign would no longer be the whole model. Cloning costs
    disk and keeps the guarantee that what was verified is what was published.
    """
    torch = _torch()
    by_storage: dict[int, list[str]] = {}
    for name, tensor in state.items():
        if isinstance(tensor, torch.Tensor):
            by_storage.setdefault(tensor.untyped_storage().data_ptr(), []).append(name)

    shared = sorted(
        name for names in by_storage.values() if len(names) > 1 for name in names
    )
    if not shared:
        return state, []

    materialised = {
        name: (tensor.clone() if name in set(shared) else tensor)
        for name, tensor in state.items()
    }
    return materialised, shared


def _verify_equivalence(original: dict[str, Any], converted_path: pathlib.Path) -> None:
    from safetensors.torch import load_file as load_safetensors

    torch = _torch()
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
    superseded: list[str] = []

    for src in sorted(root.rglob("*")):
        if not src.is_file() or ".cache" in src.parts:
            continue
        rel = src.relative_to(root)
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)

        if src.suffix in PICKLE_SUFFIXES:
            target_rel = _safetensors_name(rel)
            # Many repos ship both a pickle checkpoint and a native safetensors
            # copy of the same weights. Converting the pickle as well would
            # publish the model twice and leave two things to keep in step.
            # The native file is already the format we want, so prefer it.
            if (root / target_rel).exists():
                stage("convert", f"skipping {rel} — {target_rel} already ships natively")
                superseded.append(str(rel))
                continue

            tensors = _load_checkpoint(src)
            tensors, shared = _materialise_shared_tensors(tensors)
            if shared:
                stage("convert", f"un-tied {len(shared)} shared tensor(s) in {rel}")
            target = out / target_rel
            # contiguous() because safetensors rejects non-contiguous views.
            from safetensors.torch import save_file

            save_file({k: v.contiguous() for k, v in tensors.items()}, str(target))
            _verify_equivalence(tensors, target)
            converted.append(
                {
                    "from": str(rel),
                    "to": str(target.relative_to(out)),
                    "tensors": len(tensors),
                    "untied_tensors": shared,
                }
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
        "superseded_pickles": superseded,
        "secured_dir": str(out),
        "hashes": hash_manifest(out),
    }
    write_report(cfg.reports_dir / "convert.json", report)
    stage("convert", f"{len(converted)} converted, {len(passthrough)} copied", "ok")
    return report
