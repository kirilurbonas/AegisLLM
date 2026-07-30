"""`aegis` — the model supply chain CLI.

Each stage is a separate, idempotent subcommand so it can be demoed, debugged, or
wired into a CI job on its own. `aegis all` runs them in order.
"""

from __future__ import annotations

import pathlib

import typer

from . import aibom, convert, ingest, registry, scan, signing, verify
from .config import Settings, settings
from .report import console, stage

app = typer.Typer(
    help="AegisLLM secure model supply chain", no_args_is_help=True, add_completion=False
)


def _cfg(model: str | None, revision: str | None, mode: str | None) -> Settings:
    overrides = {}
    if model:
        overrides["model_id"] = model
    if revision:
        overrides["revision"] = revision
    if mode:
        overrides["signing_mode"] = mode
    return settings.model_copy(update=overrides) if overrides else settings


ModelOpt = typer.Option(None, "--model", "-m", help="Hugging Face model id")
RevOpt = typer.Option(None, "--revision", "-r", help="branch, tag, or commit SHA")
ModeOpt = typer.Option(None, "--mode", help="signing mode: 'key' or 'sigstore'")

# Runtime-verifier options. No defaults: the verifier should never guess which
# keys it is trusting.
RefArg = typer.Argument(..., help="digest-pinned OCI reference")
DestOpt = typer.Option(..., "--dest", help="where to place verified weights")
CosignKeyOpt = typer.Option(..., "--cosign-key", help="public key for the OCI manifest")
ModelKeyOpt = typer.Option(..., "--model-key", help="public key for the model bundle")


@app.command("ingest")
def cmd_ingest(model: str = ModelOpt, revision: str = RevOpt) -> None:
    """Download a model into quarantine, pinned to an immutable commit SHA."""
    ingest.run(_cfg(model, revision, None))


@app.command("scan")
def cmd_scan(model: str = ModelOpt) -> None:
    """Scan staged weights for malicious pickle payloads. Exits 1 on findings."""
    if scan.run(_cfg(model, None, None))["verdict"] != "PASS":
        raise typer.Exit(code=1)


@app.command("convert")
def cmd_convert(model: str = ModelOpt) -> None:
    """Convert pickle checkpoints to safetensors, verifying tensor equivalence."""
    convert.run(_cfg(model, None, None))


@app.command("aibom")
def cmd_aibom(model: str = ModelOpt) -> None:
    """Generate the CycloneDX 1.6 ML-BOM."""
    aibom.run(_cfg(model, None, None))


@app.command("sign")
def cmd_sign(model: str = ModelOpt, mode: str = ModeOpt) -> None:
    """Sign the secured model directory (weights + AIBOM)."""
    signing.run(_cfg(model, None, mode))


@app.command("push")
def cmd_push(model: str = ModelOpt) -> None:
    """Publish the signed model to the internal OCI registry."""
    registry.push(_cfg(model, None, None))


@app.command("verify")
def cmd_verify(
    model: str = ModelOpt,
    mode: str = ModeOpt,
    local: bool = typer.Option(False, "--local", help="verify on disk, skip the registry"),
    no_pull: bool = typer.Option(
        False, "--no-pull", help="re-check the already-pulled copy (for the tamper demo)"
    ),
) -> None:
    """Verify a published model. Exits 1 if it cannot prove its provenance."""
    result = verify.run(_cfg(model, None, mode), local=local, repull=not no_pull)
    if result["verdict"] != "PASS":
        raise typer.Exit(code=1)


@app.command("verify-ref")
def cmd_verify_ref(
    reference: str = RefArg,
    dest: pathlib.Path = DestOpt,
    cosign_pub: pathlib.Path = CosignKeyOpt,
    model_pub: pathlib.Path = ModelKeyOpt,
) -> None:
    """Verify a published model from its reference alone, then unpack it.

    This is what the verifier init container runs. It fails closed: any problem
    exits non-zero and the serving pod never starts.
    """
    try:
        verify.verify_ref(settings, reference, dest, cosign_pub, model_pub)
    except (signing.SignatureError, RuntimeError) as exc:
        stage("verify", f"REJECTED — {exc}", "fail")
        raise typer.Exit(code=1) from exc


@app.command("all")
def cmd_all(
    model: str = ModelOpt,
    revision: str = RevOpt,
    mode: str = ModeOpt,
    skip_registry: bool = typer.Option(
        False, "--skip-registry", help="stop after signing (no Docker/registry needed)"
    ),
) -> None:
    """Run the full supply chain: ingest → scan → convert → aibom → sign → push → verify."""
    cfg = _cfg(model, revision, mode)
    console.rule(f"[bold]AegisLLM supply chain · {cfg.model_id}")

    ingest.run(cfg)
    if scan.run(cfg)["verdict"] != "PASS":
        stage("pipeline", "halted at the scan gate", "fail")
        raise typer.Exit(code=1)
    convert.run(cfg)
    aibom.run(cfg)
    signing.run(cfg)

    if skip_registry:
        result = verify.run(cfg, local=True)
    else:
        registry.push(cfg)
        result = verify.run(cfg)

    if result["verdict"] != "PASS":
        raise typer.Exit(code=1)
    console.rule("[bold green]supply chain complete — model is signed and verified")


@app.command("tamper")
def cmd_tamper(
    model: str = ModelOpt,
    local: bool = typer.Option(False, "--local", help="tamper with the on-disk copy"),
) -> None:
    """Demo: corrupt a byte of the weights so verification must fail."""
    cfg = _cfg(model, None, None)
    root = cfg.secured_dir if local else cfg.pull_dir
    target = next(iter(sorted(root.rglob("*.safetensors"))), None)
    if target is None:
        raise typer.BadParameter(
            f"no weights found in {root} — run the pipeline first"
        )
    _flip_last_byte(target)
    stage("tamper", f"flipped one byte in {target.name}", "info")


def _flip_last_byte(path: pathlib.Path) -> None:
    with path.open("r+b") as handle:
        handle.seek(-1, 2)
        original = handle.read(1)
        handle.seek(-1, 2)
        handle.write(bytes([original[0] ^ 0xFF]))


if __name__ == "__main__":
    app()
