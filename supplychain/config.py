"""Configuration for the AegisLLM model supply chain.

Every path is derived from a single artifact root so the whole pipeline can be
relocated (or wiped) with one setting, and so an air-gapped run can point at a
mounted volume instead of the working tree.
"""

from __future__ import annotations

import pathlib

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime settings, overridable via `AEGIS_*` environment variables."""

    # protected_namespaces is cleared so `model_id` doesn't collide with pydantic's
    # reserved `model_` prefix — in this domain "model" means the ML artifact.
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_", extra="ignore", protected_namespaces=()
    )

    # The demo model is deliberately tiny: it downloads in seconds *and* it ships
    # a real pickle-based pytorch_model.bin, so the scan/convert stages have
    # something genuine to act on.
    model_id: str = "sentence-transformers/all-MiniLM-L6-v2"
    revision: str = "main"

    artifact_root: pathlib.Path = REPO_ROOT / "artifacts"

    registry: str = "localhost:5001"
    repository: str = "models"

    # "sigstore" is keyless and needs a browser OIDC flow — great for the demo,
    # impossible in CI or air-gapped. "key" uses a local EC keypair for both.
    signing_mode: str = "key"
    private_key: pathlib.Path = REPO_ROOT / "keys" / "aegis-signing.key"
    public_key: pathlib.Path = REPO_ROOT / "keys" / "aegis-signing.pub"

    # Separate from the model-signing key above: this one signs the OCI manifest
    # so Kyverno can make an admission decision without pulling the weights.
    cosign_key: pathlib.Path = REPO_ROOT / "keys" / "cosign.key"
    cosign_pub: pathlib.Path = REPO_ROOT / "keys" / "cosign.pub"
    sigstore_staging: bool = False

    @property
    def model_slug(self) -> str:
        """Registry- and filesystem-safe form of the model id."""
        return self.model_id.replace("/", "__")

    @property
    def staging_dir(self) -> pathlib.Path:
        return self.artifact_root / "staging" / self.model_slug

    @property
    def secured_dir(self) -> pathlib.Path:
        """Where safetensors-converted, about-to-be-signed weights live."""
        return self.artifact_root / "secured" / self.model_slug

    @property
    def signed_dir(self) -> pathlib.Path:
        return self.artifact_root / "signed" / self.model_slug

    @property
    def reports_dir(self) -> pathlib.Path:
        return self.artifact_root / "reports" / self.model_slug

    @property
    def pull_dir(self) -> pathlib.Path:
        """Where `verify` pulls the artifact back down to."""
        return self.artifact_root / "pulled" / self.model_slug

    @property
    def signature_path(self) -> pathlib.Path:
        return self.signed_dir / "model.sig"

    @property
    def aibom_path(self) -> pathlib.Path:
        # Deliberately inside secured_dir: signing covers the whole directory, so
        # the inventory and the weights it describes are sealed together.
        return self.secured_dir / "aibom.cdx.json"

    def image_ref(self, tag: str) -> str:
        return f"{self.registry}/{self.repository}/{self.model_id.split('/')[-1].lower()}:{tag}"


settings = Settings()
