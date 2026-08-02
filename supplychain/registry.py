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
import os
import pathlib
import shutil
import subprocess
import tempfile
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


def _discover(reference: str) -> dict[str, Any]:
    return json.loads(_oras("discover", "--plain-http", "--format", "json", reference))


def _referrers(discovered: dict[str, Any]) -> list[dict[str, Any]]:
    """Referrer list, tolerating both `oras discover --format json` shapes.

    oras 1.2.x returns them under "manifests"; 1.3.x renamed it to "referrers".
    Reading only one key means the verifier silently finds no signature when the
    binary version drifts -- and "no signature" is indistinguishable from an
    unsigned artifact, so this fails *closed* in a way that looks like an attack.
    Accept both.
    """
    return discovered.get("referrers") or discovered.get("manifests") or []


def repo_of(reference: str) -> str:
    """Strip any tag or digest, leaving <registry>/<repo>.

    Naive rsplit(":") is wrong here: `localhost:5001/models/x` has a colon in the
    registry *port*, so stripping the last colon-segment of an untagged reference
    silently yields `localhost` and every subsequent pull fails obscurely.
    """
    reference = reference.split("@")[0]
    host, _, path = reference.partition("/")
    if not path:  # no repository path at all
        return reference
    return f"{host}/{path.rsplit(':', 1)[0]}" if ":" in path else reference


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

    digest = _resolve_digest(cfg, ref)
    pinned = f"{repo_of(ref)}@{digest}"
    cosign_signed = _cosign_sign(cfg, pinned)

    payload = {
        "reference": ref,
        "digest": digest,
        "pinned_reference": pinned,
        "files": files,
        "artifact_type": ARTIFACT_TYPE,
        "cosign_signed": cosign_signed,
    }
    write_report(cfg.reports_dir / "push.json", payload)
    stage("push", f"published {payload['pinned_reference']}", "ok")
    return payload


def _resolve_digest(cfg: Settings, ref: str) -> str:
    """The manifest digest — the only form of reference a policy should trust.

    A tag is a mutable pointer; a digest is the artifact itself.
    """
    return _discover(ref)["digest"]


def ensure_cosign_key(cfg: Settings) -> None:
    """Ensure a usable cosign signing key.

    With Vault configured there is nothing to generate: the Transit key was
    created inside Vault as non-exportable, so no private key exists on this
    host to create, protect, or leak. Only the public key is materialised, and
    only so Kyverno and offline verifiers have something to check against.

    Without Vault this falls back to a local keypair with an empty passphrase —
    fine for a laptop, not for production. That gap is exactly what the Vault
    path closes; see T7 in docs/THREAT_MODEL.md.
    """
    if cfg.uses_vault:
        export_transit_public_key(cfg)
        return
    if cfg.cosign_key.exists() and cfg.cosign_pub.exists():
        return
    cfg.cosign_key.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(cfg.cosign_key.with_suffix(""))],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "COSIGN_PASSWORD": ""},
    )
    if result.returncode != 0:
        raise RuntimeError(f"cosign generate-key-pair failed:\n{result.stderr.strip()}")


def _cosign_sign(cfg: Settings, pinned_ref: str) -> bool:
    """Sign the OCI manifest with cosign, in addition to the model-signing bundle.

    Two signatures over the same artifact, answering different questions:

      * the **model-signing bundle** covers the file bytes — "these are the exact
        tensors that were scanned". Checked when the model is loaded.
      * the **cosign signature** covers the OCI manifest — "this artifact was
        published by us". Checked at *admission*, from the manifest alone,
        without pulling gigabytes of weights.

    Kyverno and the wider OCI ecosystem speak cosign; only this pipeline speaks
    model-signing. Publishing both is what lets a cluster make a decision about a
    model before it has downloaded it.
    """
    if shutil.which("cosign") is None:
        stage("push", "cosign not installed — skipping OCI manifest signature", "info")
        return False

    ensure_cosign_key(cfg)
    result = subprocess.run(
        # --use-signing-config=false is required alongside --tlog-upload=false in
        # cosign v3: the default signing config assumes a transparency log, which
        # a local/air-gapped registry has no route to.
        ["cosign", "sign", "--yes", "--tlog-upload=false", "--use-signing-config=false",
         "--allow-insecure-registry", "--key", cfg.cosign_key_uri, pinned_ref],
        capture_output=True,
        text=True,
        check=False,
        env=_cosign_env(cfg),
    )
    if result.returncode != 0:
        raise RuntimeError(f"cosign sign failed:\n{result.stderr.strip()}")
    where = "Vault Transit" if cfg.uses_vault else "local key"
    stage("push", f"cosign signature attached to the OCI manifest ({where})", "ok")
    return True


def _cosign_env(cfg: Settings) -> dict[str, str]:
    """Environment for a cosign invocation.

    VAULT_TOKEN is read from the ambient environment rather than a setting: it is
    a short-lived credential and must never end up in a config file, a report, or
    this repo.
    """
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    if cfg.uses_vault:
        env["VAULT_ADDR"] = cfg.vault_addr
        if not env.get("VAULT_TOKEN"):
            raise RuntimeError(
                "AEGIS_VAULT_ADDR is set but VAULT_TOKEN is not in the environment. "
                "Run `eval $(make vault-env)` first."
            )
    return env


def export_transit_public_key(cfg: Settings) -> pathlib.Path:
    """Write Vault's Transit *public* key to disk for verifiers.

    Public keys are not secrets — Kyverno, CI, and any offline verifier need one.
    The private half stays in Vault and cannot be exported at all.
    """
    result = subprocess.run(
        ["cosign", "public-key", "--key", cfg.cosign_key_uri],
        capture_output=True,
        text=True,
        check=False,
        env=_cosign_env(cfg),
    )
    if result.returncode != 0:
        raise RuntimeError(f"could not read the Transit public key:\n{result.stderr.strip()}")
    cfg.cosign_pub.parent.mkdir(parents=True, exist_ok=True)
    cfg.cosign_pub.write_text(result.stdout)
    return cfg.cosign_pub


def cosign_verify(cfg: Settings, pinned_ref: str, public_key: pathlib.Path) -> None:
    """Verify the OCI manifest signature. Raises on failure.

    This is the cheap check: it reads the manifest and its signature only, so a
    consumer can reject a model before downloading a single weight.
    """
    if shutil.which("cosign") is None:
        raise RuntimeError("`cosign` is not installed — cannot verify the manifest")
    result = subprocess.run(
        ["cosign", "verify", "--key", str(public_key), "--allow-insecure-registry",
         "--insecure-ignore-tlog=true", pinned_ref],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "COSIGN_PASSWORD": ""},
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"cosign could not verify {pinned_ref}:\n{result.stderr.strip()}"
        )


def pull_ref(pinned_ref: str, dest: pathlib.Path) -> pathlib.Path:
    """Pull an arbitrary pinned reference plus its signature referrer.

    Used at *runtime* by the verifier init container, which has no build reports
    to consult — only the reference the pod asked for.
    """
    dest.mkdir(parents=True, exist_ok=True)
    _oras("pull", "--plain-http", pinned_ref, "-o", str(dest))

    digest = next(
        (
            r["digest"]
            for r in _referrers(_discover(pinned_ref))
            if r.get("artifactType") == SIGNATURE_ARTIFACT_TYPE
        ),
        None,
    )
    if digest is None:
        raise RuntimeError(f"{pinned_ref} has no signature referrer — refusing to trust it")

    # A temp dir, not `<dest>.sig` beside it: the verifier runs with a read-only
    # root filesystem, so the only writable places are the model volume and /tmp.
    # The signature must also stay *outside* dest -- it covers that directory, so
    # dropping it in would change what is being verified.
    sig_dir = pathlib.Path(tempfile.mkdtemp(prefix="aegis-sig-"))
    repo = repo_of(pinned_ref)
    _oras("pull", "--plain-http", f"{repo}@{digest}", "-o", str(sig_dir))
    return sig_dir


def pull(cfg: Settings) -> dict[str, Any]:
    """Pull the model and its signature referrer back into a clean directory."""
    ref = cfg.image_ref(_tag(cfg))
    if cfg.pull_dir.exists():
        shutil.rmtree(cfg.pull_dir)
    cfg.pull_dir.mkdir(parents=True)

    stage("pull", f"pulling {ref}")
    _oras("pull", "--plain-http", ref, "-o", str(cfg.pull_dir))

    digest = next(
        (
            r["digest"]
            for r in _referrers(_discover(ref))
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
    repo = repo_of(ref)
    _oras("pull", "--plain-http", f"{repo}@{digest}", "-o", str(sig_dir))

    return {
        "reference": ref,
        "model_dir": str(cfg.pull_dir),
        "signature_dir": str(sig_dir),
        "signature_digest": digest,
    }
