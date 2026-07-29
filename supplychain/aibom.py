"""Stage 4 — generate an AI Bill of Materials (CycloneDX ML-BOM).

An SBOM answers "what is in this build?". An AIBOM answers the same question for
a model: where the weights came from, which immutable revision, under what
licence, and what the hash of every shipped file is.

That last part is what makes it a security control rather than paperwork — the
BOM is signed alongside the weights, so the inventory and the artifact cannot
drift apart without breaking the signature.
"""

from __future__ import annotations

from typing import Any

from cyclonedx.model import (
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    Property,
    XsUri,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import DisjunctiveLicense
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

from .config import Settings
from .report import read_report, stage, write_report


def build_bom(cfg: Settings, ingest: dict[str, Any], convert: dict[str, Any]) -> Bom:
    root = Component(
        name=cfg.model_id.split("/")[-1],
        group=cfg.model_id.split("/")[0] if "/" in cfg.model_id else None,
        type=ComponentType.MACHINE_LEARNING_MODEL,
        version=ingest["resolved_sha"],
        description=f"Open-weights model ingested from {ingest['source_url']}",
        licenses=(
            [DisjunctiveLicense(id=ingest["license"])] if ingest.get("license") else None
        ),
        external_references=[
            ExternalReference(
                type=ExternalReferenceType.DISTRIBUTION,
                url=XsUri(ingest["source_url"]),
            )
        ],
        properties=[
            Property(name="aegis:requested-revision", value=ingest["requested_revision"]),
            Property(name="aegis:resolved-sha", value=ingest["resolved_sha"]),
            Property(name="aegis:scan-verdict", value="PASS"),
            Property(
                name="aegis:weights-format",
                value="safetensors" if convert["converted"] else "safetensors (native)",
            ),
        ],
    )

    # Each shipped file becomes a subcomponent carrying its own hash, so a
    # verifier can pin the inventory down to individual bytes.
    for rel, digest in convert["hashes"].items():
        root.components.add(
            Component(
                name=rel,
                type=ComponentType.FILE,
                hashes=[HashType(alg=HashAlgorithm.SHA_256, content=digest)],
            )
        )

    bom = Bom()
    bom.metadata.component = root
    return bom


def run(cfg: Settings) -> dict[str, Any]:
    ingest = read_report(cfg.reports_dir / "ingest.json")
    convert = read_report(cfg.reports_dir / "convert.json")

    bom = build_bom(cfg, ingest, convert)
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)

    cfg.aibom_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.aibom_path.write_text(outputter.output_as_string(indent=2))

    payload = {
        "aibom_path": str(cfg.aibom_path),
        "spec_version": "1.6",
        "component_count": len(convert["hashes"]) + 1,
        "license": ingest.get("license"),
        "resolved_sha": ingest["resolved_sha"],
    }
    write_report(cfg.reports_dir / "aibom.json", payload)
    stage("aibom", f"CycloneDX 1.6 ML-BOM, {payload['component_count']} components", "ok")
    return payload
