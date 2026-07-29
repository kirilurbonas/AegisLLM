"""Stage 5 — cryptographically sign the secured model.

Signing is what turns "we scanned it once" into a durable, transferable claim.
The signature covers every file in `secured_dir` — weights *and* AIBOM — so
neither can be swapped without detection.

Two modes, and the split matters:

  * ``sigstore`` — keyless. Identity comes from an OIDC flow and the signature is
    recorded in a public transparency log. Excellent provenance, no long-lived
    key to leak. Requires a browser and internet, so it cannot run in CI or
    air-gapped.
  * ``key`` — a local elliptic-curve keypair. Works offline and unattended. This
    is the default here precisely because Pillar 5 promises an air-gapped run,
    and retrofitting an offline path later is how projects end up stuck.

Both produce the same artifact shape, so downstream stages don't care which ran.
"""

from __future__ import annotations

import subprocess
from typing import Any

from model_signing import signing as ms_signing
from model_signing import verifying as ms_verifying

from .config import Settings
from .report import stage, write_report


class SignatureError(RuntimeError):
    """Raised when a model fails verification — the tamper-demo failure path."""


def ensure_keypair(cfg: Settings) -> None:
    """Generate an EC P-256 keypair for `key` mode if one isn't present."""
    if cfg.private_key.exists() and cfg.public_key.exists():
        return
    cfg.private_key.parent.mkdir(parents=True, exist_ok=True)
    stage("sign", f"generating signing keypair at {cfg.private_key.parent}")
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
         "-out", str(cfg.private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "ec", "-in", str(cfg.private_key), "-pubout",
         "-out", str(cfg.public_key)],
        check=True,
        capture_output=True,
    )
    cfg.private_key.chmod(0o600)


def _signer(cfg: Settings) -> ms_signing.Config:
    config = ms_signing.Config()
    if cfg.signing_mode == "sigstore":
        return config.use_sigstore_signer(use_staging=cfg.sigstore_staging)
    ensure_keypair(cfg)
    return config.use_elliptic_key_signer(private_key=cfg.private_key)


def _verifier(cfg: Settings, identity: dict[str, Any] | None) -> ms_verifying.Config:
    config = ms_verifying.Config()
    if cfg.signing_mode == "sigstore":
        identity = identity or {}
        return config.use_sigstore_verifier(
            identity=identity.get("identity", ""),
            oidc_issuer=identity.get("oidc_issuer", ""),
            use_staging=cfg.sigstore_staging,
        )
    return config.use_elliptic_key_verifier(public_key=cfg.public_key)


def run(cfg: Settings) -> dict[str, Any]:
    if not cfg.secured_dir.exists():
        raise FileNotFoundError("nothing to sign — run `aegis convert` first")
    if not cfg.aibom_path.exists():
        raise FileNotFoundError("no AIBOM present — run `aegis aibom` first")

    cfg.signed_dir.mkdir(parents=True, exist_ok=True)
    stage("sign", f"signing {cfg.secured_dir.name} in '{cfg.signing_mode}' mode")
    _signer(cfg).sign(cfg.secured_dir, cfg.signature_path)

    payload = {
        "mode": cfg.signing_mode,
        "signature": str(cfg.signature_path),
        "signed_dir": str(cfg.secured_dir),
        "public_key": str(cfg.public_key) if cfg.signing_mode == "key" else None,
    }
    write_report(cfg.reports_dir / "sign.json", payload)
    stage("sign", f"signature written to {cfg.signature_path.name}", "ok")
    return payload


def verify_path(cfg: Settings, model_dir, signature_path, identity=None) -> None:
    """Verify a directory against a signature. Raises SignatureError on mismatch."""
    try:
        _verifier(cfg, identity).verify(model_dir, signature_path)
    except Exception as exc:  # model-signing raises a family of typed errors
        raise SignatureError(str(exc)) from exc
