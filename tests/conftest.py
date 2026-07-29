"""Shared fixtures — including a genuinely malicious model checkpoint.

The malicious fixture is the point. A scan gate that has never been shown to stop
a real payload is decoration; these tests build a checkpoint whose `__reduce__`
invokes `os.system` and assert the pipeline refuses it.

The payload is inert by construction: it would run `echo`, and it is never loaded
with `torch.load` at default settings anywhere in the test suite.
"""

from __future__ import annotations

import os
import pathlib

import pytest
import torch

from supplychain.config import Settings


class _MaliciousPayload:
    """Executes a shell command when unpickled. The classic model-hub attack."""

    def __reduce__(self):
        return (os.system, ("echo aegis-payload-executed",))


@pytest.fixture
def malicious_checkpoint(tmp_path: pathlib.Path) -> pathlib.Path:
    """A torch checkpoint that looks legitimate but carries a code-exec payload."""
    model_dir = tmp_path / "malicious-model"
    model_dir.mkdir()
    torch.save(
        {"encoder.weight": torch.zeros(4, 4), "backdoor": _MaliciousPayload()},
        model_dir / "pytorch_model.bin",
    )
    (model_dir / "config.json").write_text('{"model_type": "bert"}')
    return model_dir


@pytest.fixture
def benign_checkpoint(tmp_path: pathlib.Path) -> pathlib.Path:
    model_dir = tmp_path / "benign-model"
    model_dir.mkdir()
    torch.save(
        {"encoder.weight": torch.ones(4, 4), "encoder.bias": torch.zeros(4)},
        model_dir / "pytorch_model.bin",
    )
    (model_dir / "config.json").write_text('{"model_type": "bert"}')
    return model_dir


@pytest.fixture
def cfg(tmp_path: pathlib.Path) -> Settings:
    """Settings pointed entirely at a throwaway artifact root."""
    return Settings(
        model_id="aegis-test/fixture-model",
        artifact_root=tmp_path / "artifacts",
        private_key=tmp_path / "keys" / "test.key",
        public_key=tmp_path / "keys" / "test.pub",
        signing_mode="key",
    )


@pytest.fixture
def staged(cfg: Settings, request) -> Settings:
    """Place a checkpoint fixture into cfg's staging dir, as ingest would."""
    source: pathlib.Path = request.getfixturevalue(request.param)
    cfg.staging_dir.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        (cfg.staging_dir / item.name).write_bytes(item.read_bytes())
    return cfg
