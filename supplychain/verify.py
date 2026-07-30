"""Stage 7 — verify a published model before anything is allowed to load it.

This is the stage the whole pillar exists to make possible. It pulls the artifact
back out of the registry as a consumer would, with no access to the local build
state, and answers one question: *can this model prove it is what it claims?*

Three independent checks, all of which must pass:

  1. the AIBOM is present and its recorded hashes match the pulled files;
  2. no pickle-format weights snuck back in;
  3. the signature verifies over the pulled directory.

Check 3 is the one that catches a tampered byte, which is the demo.
"""

from __future__ import annotations

import pathlib
from typing import Any

from . import registry, signing
from .config import Settings
from .report import read_report, sha256_file, stage, write_report
from .signing import SignatureError

PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt"}


def verify_ref(
    cfg: Settings,
    pinned_ref: str,
    dest: pathlib.Path,
    cosign_pub: pathlib.Path,
    model_pub: pathlib.Path,
) -> dict[str, Any]:
    """Verify a published model given only its pinned reference.

    This is the runtime path: it runs as an init container beside a serving pod,
    with no access to build reports or the machine that produced the model. It is
    also the enforcement point — every failure raises, the init container exits
    non-zero, and the pod never starts. **Fail closed.**

    Order matters. The manifest signature is checked *before* the weights are
    pulled, so an unsigned or foreign-signed model costs a manifest fetch rather
    than a multi-gigabyte download.
    """
    if "@sha256:" not in pinned_ref:
        # A tag can be repointed after a policy approved it. A digest cannot.
        raise SignatureError(f"reference must be digest-pinned, got: {pinned_ref}")

    stage("verify", f"checking manifest signature for {pinned_ref.split('@')[1][:19]}…")
    try:
        registry.cosign_verify(cfg, pinned_ref, cosign_pub)
    except RuntimeError as exc:
        raise SignatureError(str(exc)) from exc
    stage("verify", "manifest signature valid — proceeding to download", "ok")

    sig_dir = registry.pull_ref(pinned_ref, dest)

    aibom = dest / "aibom.cdx.json"
    if not aibom.exists():
        raise SignatureError("no AIBOM in the artifact — refusing to serve it")

    pickles = [str(p.relative_to(dest)) for p in dest.rglob("*") if p.suffix in PICKLE_SUFFIXES]
    if pickles:
        raise SignatureError(f"executable pickle weights present: {pickles}")

    runtime_cfg = cfg.model_copy(update={"signing_mode": "key", "public_key": model_pub})
    signing.verify_path(runtime_cfg, dest, sig_dir / cfg.signature_path.name)

    stage("verify", f"ACCEPTED — weights verified into {dest}", "ok")
    return {"verdict": "PASS", "reference": pinned_ref, "model_dir": str(dest)}


def _check_hashes(model_dir: pathlib.Path, expected: dict[str, str]) -> list[str]:
    problems = []
    for rel, digest in expected.items():
        candidate = model_dir / rel
        if not candidate.exists():
            problems.append(f"missing file listed in AIBOM: {rel}")
        elif sha256_file(candidate) != digest:
            problems.append(f"hash mismatch: {rel}")
    return problems


def run(cfg: Settings, local: bool = False, repull: bool = True) -> dict[str, Any]:
    """Verify the published artifact.

    `local=True` skips the registry round-trip and verifies what's on disk —
    useful before pushing, and in CI without a registry. `repull=False` re-checks
    an already-pulled copy without overwriting it, which is what the tamper demo
    needs (a fresh pull would helpfully undo the corruption)."""
    if local:
        model_dir = cfg.secured_dir
        signature = cfg.signature_path
        source = "local"
    elif not repull:
        model_dir = cfg.pull_dir
        signature = cfg.pull_dir.parent / f"{cfg.pull_dir.name}.sig" / cfg.signature_path.name
        source = f"{cfg.pull_dir} (previously pulled)"
        if not model_dir.exists():
            raise FileNotFoundError(f"nothing pulled at {model_dir} — run `aegis verify` first")
    else:
        pulled = registry.pull(cfg)
        model_dir = pathlib.Path(pulled["model_dir"])
        signature = pathlib.Path(pulled["signature_dir"]) / cfg.signature_path.name
        source = pulled["reference"]

    failures: list[str] = []

    expected = read_report(cfg.reports_dir / "convert.json")["hashes"]
    failures += _check_hashes(model_dir, expected)

    pickles = [
        str(p.relative_to(model_dir))
        for p in model_dir.rglob("*")
        if p.suffix in PICKLE_SUFFIXES
    ]
    if pickles:
        failures.append(f"executable pickle weights present: {pickles}")

    if not (model_dir / "aibom.cdx.json").exists():
        failures.append("AIBOM missing from the published artifact")

    try:
        signing.verify_path(cfg, model_dir, signature)
        stage("verify", "signature valid", "ok")
    except signing.SignatureError as exc:
        failures.append(f"signature verification failed: {exc}")

    verdict = "FAIL" if failures else "PASS"
    report = {"verdict": verdict, "source": source, "failures": failures}
    write_report(cfg.reports_dir / "verify.json", report)

    if failures:
        stage("verify", f"REJECTED — {len(failures)} failure(s)", "fail")
        for failure in failures:
            stage("", f"  · {failure}", "fail")
    else:
        stage("verify", f"ACCEPTED — {source}", "ok")
    return report
