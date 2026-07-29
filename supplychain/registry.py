"""Stage 6 — publish the signed model to an internal OCI registry.

This is the air-gap boundary. After this point nothing in the platform ever
resolves huggingface.co: the registry *is* the source of truth, and Kubernetes
pulls models the same way it pulls container images.

Layout of the published artifact:

    <registry>/models/<name>:<sha>          weights + AIBOM (safetensors only)
      └── referrer: application/vnd.aegis.signature.v1   the signature bundle

The signature is attached as an OCI *referrer* rather than baked into the image,
so it can be fetched and checked independently — which is exactly what a Kyverno
admission policy will need to do in Pillar 2.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from .config import Settings
from .report import read_report, stage, write_report

ARTIFACT_TYPE = "application/vnd.aegis.model.v1+json"
SIGNATURE_ARTIFACT_TYPE = "application/vnd.aegis.signature.v1"


def _oras(*args: str, cwd=None) -> str:
    if shutil.which("oras") is None:
        raise RuntimeError("`oras` is not installed — run `make tools`")
    result = subprocess.run(
        ["oras", *args], cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"oras {' '.join(args)} failed:\n{result.stderr.strip()}")
    return result.stdout


def _tag(cfg: Settings) -> str:
    return read_report(cfg.reports_dir / "ingest.json")["resolved_sha"]


def push(cfg: Settings) -> dict[str, Any]:
    ref = cfg.image_ref(_tag(cfg))
    files = sorted(
        str(p.relative_to(cfg.secured_dir))
        for p in cfg.secured_dir.rglob("*")
        if p.is_file()
    )
    stage("push", f"pushing {len(files)} file(s) to {ref}")
    _oras(
        "push", "--plain-http", "--artifact-type", ARTIFACT_TYPE, ref, *files,
        cwd=cfg.secured_dir,
    )

    # Attach the signature as a referrer of the model manifest.
    stage("push", "attaching signature as an OCI referrer")
    _oras(
        "attach", "--plain-http", "--artifact-type", SIGNATURE_ARTIFACT_TYPE,
        ref, cfg.signature_path.name,
        cwd=cfg.signature_path.parent,
    )

    payload = {"reference": ref, "files": files, "artifact_type": ARTIFACT_TYPE}
    write_report(cfg.reports_dir / "push.json", payload)
    stage("push", f"published {ref}", "ok")
    return payload


def pull(cfg: Settings) -> dict[str, Any]:
    """Pull the model and its signature referrer back into a clean directory."""
    ref = cfg.image_ref(_tag(cfg))
    if cfg.pull_dir.exists():
        shutil.rmtree(cfg.pull_dir)
    cfg.pull_dir.mkdir(parents=True)

    stage("pull", f"pulling {ref}")
    _oras("pull", "--plain-http", ref, "-o", str(cfg.pull_dir))

    discovered = json.loads(_oras("discover", "--plain-http", "--format", "json", ref))
    digest = next(
        (
            r["digest"]
            for r in discovered.get("referrers", [])
            if r.get("artifactType") == SIGNATURE_ARTIFACT_TYPE
        ),
        None,
    )
    # An artifact with no signature attached is not "unverified", it is rejected.
    # There is no path in this pipeline where unsigned weights get used.
    if digest is None:
        raise RuntimeError(f"{ref} has no signature referrer — refusing to trust it")

    sig_dir = cfg.pull_dir.parent / f"{cfg.pull_dir.name}.sig"
    if sig_dir.exists():
        shutil.rmtree(sig_dir)
    sig_dir.mkdir(parents=True)
    repo = ref.rsplit(":", 1)[0]
    _oras("pull", "--plain-http", f"{repo}@{digest}", "-o", str(sig_dir))

    return {
        "reference": ref,
        "model_dir": str(cfg.pull_dir),
        "signature_dir": str(sig_dir),
        "signature_digest": digest,
    }
