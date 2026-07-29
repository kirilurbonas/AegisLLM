"""Stage 1 — pull an untrusted model from Hugging Face into a staging area.

The staging area is quarantine: nothing here is trusted, nothing here is served.
The one security-relevant decision made at this stage is *pinning* — we resolve
whatever revision was requested down to an immutable commit SHA and record it.
A branch name is not provenance; a commit SHA is.
"""

from __future__ import annotations

import pathlib
import shutil
from typing import Any

from huggingface_hub import HfApi, snapshot_download

from .config import Settings
from .report import stage, write_report

# Weight formats worth pulling. Everything else (tokenizers, configs, cards) is
# small and comes along for free.
ALLOW_PATTERNS = [
    "*.json",
    "*.txt",
    "*.md",
    "*.bin",
    "*.safetensors",
    "*.model",
]

# Alternate-runtime exports (OpenVINO IR, ONNX, TensorFlow) also use `.bin`/`.h5`
# but are not torch checkpoints, so the convert stage cannot secure them. Rather
# than ship weights this pipeline can't vouch for, we don't ingest them at all.
IGNORE_PATTERNS = ["openvino/*", "onnx/*", "tf_model*", "flax_model*", "rust_model*"]


def resolve_revision(cfg: Settings) -> dict[str, Any]:
    info = HfApi().model_info(cfg.model_id, revision=cfg.revision)
    return {
        "model_id": cfg.model_id,
        "requested_revision": cfg.revision,
        "resolved_sha": info.sha,
        "license": (info.card_data or {}).get("license"),
        "source_url": f"https://huggingface.co/{cfg.model_id}",
        "siblings": [s.rfilename for s in (info.siblings or [])],
    }


def run(cfg: Settings) -> dict[str, Any]:
    stage("ingest", f"resolving {cfg.model_id}@{cfg.revision}")
    meta = resolve_revision(cfg)

    cfg.staging_dir.mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=cfg.model_id,
        revision=meta["resolved_sha"],
        local_dir=str(cfg.staging_dir),
        allow_patterns=ALLOW_PATTERNS,
        ignore_patterns=IGNORE_PATTERNS,
    )

    # snapshot_download leaves its own bookkeeping cache inside local_dir. It is
    # not part of the model, and leaving it there would flood the scanner with
    # .lock/.metadata files it cannot parse — quarantine holds model files only.
    shutil.rmtree(cfg.staging_dir / ".cache", ignore_errors=True)

    files = sorted(
        str(p.relative_to(cfg.staging_dir))
        for p in cfg.staging_dir.rglob("*")
        if p.is_file() and ".cache" not in p.parts
    )
    meta["staged_files"] = files
    meta["staging_dir"] = str(cfg.staging_dir)

    stage("ingest", f"pinned to {meta['resolved_sha'][:12]}, {len(files)} files", "ok")
    write_report(cfg.reports_dir / "ingest.json", meta)
    return meta


def staged_root(cfg: Settings) -> pathlib.Path:
    if not cfg.staging_dir.exists():
        raise FileNotFoundError(f"nothing staged at {cfg.staging_dir} — run `aegis ingest`")
    return cfg.staging_dir
