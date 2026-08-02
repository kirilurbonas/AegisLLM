"""Conversion fidelity, AIBOM contents, and the sign/verify/tamper contract."""

from __future__ import annotations

import json

import pytest
import torch
from safetensors.torch import load_file

from supplychain import aibom, convert, scan, signing, verify
from supplychain.report import write_report


@pytest.fixture
def secured(staged):
    """A staged model taken through scan → convert → aibom → sign."""
    # `verify` reads ingest.json for provenance; the real stage writes it.
    write_report(
        staged.reports_dir / "ingest.json",
        {
            "model_id": staged.model_id,
            "requested_revision": "main",
            "resolved_sha": "0" * 40,
            "license": "apache-2.0",
            "source_url": f"https://huggingface.co/{staged.model_id}",
        },
    )
    scan.run(staged)
    convert.run(staged)
    aibom.run(staged)
    signing.run(staged)
    return staged


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_conversion_is_tensor_faithful(staged):
    scan.run(staged)
    convert.run(staged)

    original = torch.load(
        staged.staging_dir / "pytorch_model.bin", map_location="cpu", weights_only=True
    )
    converted = load_file(str(staged.secured_dir / "model.safetensors"))

    assert set(converted) == set(original)
    for name, tensor in original.items():
        assert torch.equal(tensor, converted[name])


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_pickle_weights_do_not_survive_conversion(staged):
    scan.run(staged)
    convert.run(staged)

    survivors = [p.name for p in staged.secured_dir.rglob("*.bin")]
    assert survivors == [], f"pickle weights leaked into the secured dir: {survivors}"


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_aibom_records_provenance_and_hashes(secured):
    bom = json.loads(secured.aibom_path.read_text())
    root = bom["metadata"]["component"]

    assert root["type"] == "machine-learning-model"
    assert root["version"] == "0" * 40, "AIBOM must pin the immutable revision"

    properties = {p["name"]: p["value"] for p in root["properties"]}
    assert properties["aegis:scan-verdict"] == "PASS"

    # Every shipped file is inventoried with a SHA-256.
    subcomponents = {c["name"]: c for c in root["components"]}
    assert "model.safetensors" in subcomponents
    for component in subcomponents.values():
        assert component["hashes"][0]["alg"] == "SHA-256"


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_signed_model_verifies(secured):
    assert verify.run(secured, local=True)["verdict"] == "PASS"


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_tampered_weights_fail_verification(secured):
    """One flipped byte must be enough to reject the model."""
    target = secured.secured_dir / "model.safetensors"
    with target.open("r+b") as handle:
        handle.seek(-1, 2)
        last = handle.read(1)
        handle.seek(-1, 2)
        handle.write(bytes([last[0] ^ 0xFF]))

    report = verify.run(secured, local=True)

    assert report["verdict"] == "FAIL"
    assert any("signature verification failed" in f for f in report["failures"])


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_tampered_aibom_fails_verification(secured):
    """The inventory is inside the signature envelope, so it can't be edited."""
    bom = json.loads(secured.aibom_path.read_text())
    bom["metadata"]["component"]["version"] = "f" * 40
    secured.aibom_path.write_text(json.dumps(bom))

    assert verify.run(secured, local=True)["verdict"] == "FAIL"


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_verification_fails_against_a_foreign_key(secured, tmp_path):
    """A valid signature from the wrong signer is still a rejection."""
    foreign = secured.model_copy(
        update={
            "private_key": tmp_path / "foreign" / "k.key",
            "public_key": tmp_path / "foreign" / "k.pub",
        }
    )
    signing.ensure_keypair(foreign)

    assert verify.run(foreign, local=True)["verdict"] == "FAIL"


@pytest.mark.parametrize(
    "reference,expected",
    [
        # The bug this guards: a registry port is a colon that is not a tag.
        ("localhost:5001/models/x@sha256:abc", "localhost:5001/models/x"),
        ("localhost:5001/models/x:v1", "localhost:5001/models/x"),
        ("localhost:5001/models/x", "localhost:5001/models/x"),
        ("ghcr.io/kiril/aegis:1.0", "ghcr.io/kiril/aegis"),
        ("ghcr.io/kiril/aegis", "ghcr.io/kiril/aegis"),
    ],
)
def test_repo_of_strips_tags_and_digests_not_ports(reference, expected):
    from supplychain.registry import repo_of

    assert repo_of(reference) == expected


@pytest.fixture
def tied_weights_checkpoint(tmp_path):
    """A GPT-2-shaped checkpoint where lm_head aliases the embedding."""
    embedding = torch.arange(12, dtype=torch.float32).reshape(4, 3)
    model_dir = tmp_path / "tied-model"
    model_dir.mkdir()
    torch.save(
        {"transformer.wte.weight": embedding, "lm_head.weight": embedding},
        model_dir / "pytorch_model.bin",
    )
    (model_dir / "config.json").write_text('{"architectures": ["GPT2LMHeadModel"]}')
    return model_dir


@pytest.mark.parametrize("staged", ["tied_weights_checkpoint"], indirect=True)
def test_tied_weights_convert_without_losing_tensors(staged):
    """safetensors cannot express aliasing; nothing may be silently dropped."""
    scan.run(staged)
    report = convert.run(staged)

    converted = load_file(str(staged.secured_dir / "model.safetensors"))

    assert set(converted) == {"transformer.wte.weight", "lm_head.weight"}
    assert torch.equal(converted["transformer.wte.weight"], converted["lm_head.weight"])
    assert sorted(report["converted"][0]["untied_tensors"]) == [
        "lm_head.weight",
        "transformer.wte.weight",
    ]
