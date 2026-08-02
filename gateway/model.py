"""Model loading — safetensors only, from a local directory only.

The gateway deliberately cannot fetch a model. It reads the directory the
verifier init container populated after checking signatures, and nothing else.
No registry client, no Hugging Face client, no network path to either. If the
verifier failed, the volume is empty and this refuses to start.

`weights_only`-style safety is not enough here; the loader simply has no code
path that opens a pickle. A `pytorch_model.bin` sitting on the volume is inert.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

SAFETENSORS = "*.safetensors"
PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt"}


@dataclasses.dataclass
class InferenceOutput:
    text: str | None = None
    embedding: list[float] | None = None


class ModelBackend:
    """Base class. `kind` drives which response shape the gateway returns."""

    kind = "unknown"

    def __init__(self, model_dir: pathlib.Path) -> None:
        self.model_dir = model_dir
        self._aibom = _read_aibom(model_dir)

    def infer(self, text: str, max_tokens: int) -> InferenceOutput:
        raise NotImplementedError

    def provenance(self) -> dict[str, Any]:
        """Provenance straight from the signed AIBOM that shipped with the weights."""
        if not self._aibom:
            return {"provenance": "unavailable", "backend": self.kind}
        component = self._aibom.get("metadata", {}).get("component", {})
        properties = {
            p["name"]: p["value"] for p in component.get("properties", [])
        }
        return {
            "backend": self.kind,
            "name": component.get("name"),
            "group": component.get("group"),
            "revision": component.get("version"),
            "licenses": [
                lic.get("license", {}).get("id")
                for lic in component.get("licenses", [])
            ],
            "scan_verdict": properties.get("aegis:scan-verdict"),
            "weights_format": properties.get("aegis:weights-format"),
            "file_count": len(component.get("components", [])),
        }


class EmbeddingBackend(ModelBackend):
    kind = "embedding"

    def __init__(self, model_dir: pathlib.Path) -> None:
        super().__init__(model_dir)
        from transformers import AutoModel, AutoTokenizer

        self._tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        self._model = AutoModel.from_pretrained(str(model_dir), use_safetensors=True)
        self._model.eval()

    def infer(self, text: str, max_tokens: int) -> InferenceOutput:
        import torch

        with torch.no_grad():
            encoded = self._tokenizer(
                text, return_tensors="pt", truncation=True, max_length=512
            )
            output = self._model(**encoded)
            # Mean pooling over the attention mask — the standard sentence
            # embedding for this model family.
            mask = encoded["attention_mask"].unsqueeze(-1).float()
            pooled = (output.last_hidden_state * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
        return InferenceOutput(embedding=pooled[0].tolist())


class CausalLMBackend(ModelBackend):
    kind = "generative"

    def __init__(self, model_dir: pathlib.Path) -> None:
        super().__init__(model_dir)
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token
        self._model = AutoModelForCausalLM.from_pretrained(
            str(model_dir), use_safetensors=True
        )
        self._model.eval()

    def infer(self, text: str, max_tokens: int) -> InferenceOutput:
        import torch

        with torch.no_grad():
            encoded = self._tokenizer(
                text, return_tensors="pt", truncation=True, max_length=512
            )
            generated = self._model.generate(
                **encoded,
                # Hard cap regardless of what the caller asked for: LLM10 is
                # enforced here as well as at the quota, because generation
                # length is the actual cost driver.
                max_new_tokens=min(max_tokens, 256),
                do_sample=False,
                pad_token_id=self._tokenizer.pad_token_id,
            )
        completion = self._tokenizer.decode(
            generated[0][encoded["input_ids"].shape[1]:], skip_special_tokens=True
        )
        return InferenceOutput(text=completion)


def _read_aibom(model_dir: pathlib.Path) -> dict[str, Any] | None:
    aibom = model_dir / "aibom.cdx.json"
    if not aibom.exists():
        return None
    try:
        return json.loads(aibom.read_text())
    except json.JSONDecodeError:
        return None


def load_backend(model_dir: pathlib.Path) -> ModelBackend:
    """Pick a backend from the model's own config. Fails closed."""
    if not model_dir.is_dir():
        raise RuntimeError(
            f"{model_dir} does not exist — the verifier init container did not run, "
            "or it refused the model. Refusing to start."
        )
    if not list(model_dir.glob(SAFETENSORS)):
        raise RuntimeError(
            f"no safetensors weights in {model_dir}. This gateway does not load "
            "pickle checkpoints under any circumstances."
        )

    config_path = model_dir / "config.json"
    architectures = []
    if config_path.exists():
        architectures = json.loads(config_path.read_text()).get("architectures") or []

    if any("CausalLM" in arch or "LMHead" in arch for arch in architectures):
        return CausalLMBackend(model_dir)
    return EmbeddingBackend(model_dir)
