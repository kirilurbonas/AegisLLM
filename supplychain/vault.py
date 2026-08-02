"""Minimal Vault client for the parts of the supply chain that need secrets.

Deliberately hand-rolled over `urllib` rather than pulling in `hvac`: this needs
four API calls, and a security-critical component earns its dependencies. Fewer
transitive packages is itself a supply-chain property, which is a slightly
awkward thing to ignore in a repo about supply-chain security.

Two different trust levels live here, and the difference matters:

* The **cosign** key is a Vault *Transit* key. It is created non-exportable, so
  signing is an API call and no private key exists outside Vault. Nothing in this
  module can read it, and neither can an operator holding the root token.
* The **model-signing** key is a kv-v2 secret. `model_signing` offers only
  elliptic-key, certificate, PKCS#11 and sigstore signers — there is no KMS
  backend — so the key has to be materialised to sign. It is generated in
  memory, stored in Vault, and fetched to a 0600 file under /dev/shm (tmpfs, so
  it never reaches persistent storage) for the moments a signature is produced.
  That is a real improvement over a key committed beside the code, and it is
  weaker than Transit. The threat model says so rather than blurring the two.
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import urllib.error
import urllib.request
from typing import Any

from .config import Settings

MODEL_KEY_PATH = "signing/model"


class VaultError(RuntimeError):
    pass


def _token() -> str:
    token = os.environ.get("VAULT_TOKEN", "")
    if not token:
        raise VaultError(
            "VAULT_TOKEN is not set. Run `eval $(make vault-env)` first. "
            "It is read from the environment on purpose — a short-lived "
            "credential must never live in a config file or this repo."
        )
    return token


def _request(cfg: Settings, method: str, path: str, body: dict | None = None) -> dict[str, Any]:
    url = f"{cfg.vault_addr.rstrip('/')}/v1/{path.lstrip('/')}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-Vault-Token", _token())
    if data:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise VaultError(f"vault {method} {path} failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise VaultError(
            f"cannot reach Vault at {cfg.vault_addr}: {exc.reason}. "
            "Is the port-forward running? `make vault-port-forward`"
        ) from exc


def kv_get(cfg: Settings, path: str) -> dict[str, str] | None:
    try:
        payload = _request(cfg, "GET", f"aegis/data/{path}")
    except VaultError as exc:
        if "404" in str(exc):
            return None
        raise
    return payload.get("data", {}).get("data")


def kv_put(cfg: Settings, path: str, data: dict[str, str]) -> None:
    _request(cfg, "POST", f"aegis/data/{path}", {"data": data})


def generate_model_signing_key(cfg: Settings, *, rotate: bool = False) -> bool:
    """Create the model-signing keypair inside this process and store it in Vault.

    The private key is held only in memory here and PEM-encoded straight into the
    API call — it is never written to the working tree. Returns True if a new key
    was created.
    """
    if not rotate and kv_get(cfg, MODEL_KEY_PATH):
        return False

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    kv_put(cfg, MODEL_KEY_PATH, {"private": private_pem, "public": public_pem})
    return True


def materialise_model_signing_key(cfg: Settings) -> tuple[pathlib.Path, pathlib.Path]:
    """Fetch the model-signing key to a private tmpfs file for one signing run.

    /dev/shm is tmpfs on Linux, so the key never touches persistent storage. On
    macOS there is no equivalent, and the fallback is a 0600 file in the system
    temp dir — noted here rather than pretended away. Callers must delete these
    when finished; `signing.py` does so in a finally block.
    """
    secret = kv_get(cfg, MODEL_KEY_PATH)
    if not secret:
        raise VaultError(
            "no model-signing key in Vault — run `aegis keys rotate --init`"
        )

    shm = pathlib.Path("/dev/shm")
    directory = shm if shm.is_dir() and os.access(shm, os.W_OK) else None
    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="aegis-key-", dir=directory))
    tmpdir.chmod(0o700)

    private_path = tmpdir / "model.key"
    public_path = tmpdir / "model.pub"
    private_path.write_text(secret["private"])
    private_path.chmod(0o600)
    public_path.write_text(secret["public"])
    return private_path, public_path


def public_key(cfg: Settings) -> str:
    secret = kv_get(cfg, MODEL_KEY_PATH)
    if not secret:
        raise VaultError("no model-signing key in Vault")
    return secret["public"]
