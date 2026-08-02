"""The inference gateway — the only door to the model.

Design rules, each of which is a control rather than a preference:

* The model is loaded from a **local directory only**, the one the verifier init
  container wrote after checking its signature. The gateway has no registry
  credentials and never fetches weights. If verification did not happen, there is
  nothing on the volume and the gateway refuses to start.
* It loads **safetensors only**. Even if a pickle checkpoint appeared on the
  volume, the loader would not open it.
* There is exactly one inference route, and it applies the guardrails inline.
  Guardrails as optional middleware are a route away from being forgotten; a
  single narrow door is easier to review than a policy applied by convention.
* Nothing about the failure is explained to the caller beyond a category. A
  detailed rejection reason is a free oracle for tuning an attack.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import pathlib
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .guardrails import GuardrailConfig, InputGuardrail, OutputGuardrail
from .limits import RateLimiter
from .model import ModelBackend, load_backend

LOG = logging.getLogger("aegis.gateway")
logging.basicConfig(level=logging.INFO, format="%(message)s")

MODEL_DIR = pathlib.Path(os.getenv("AEGIS_MODEL_DIR", "/models"))
SYSTEM_PROMPT = os.getenv(
    "AEGIS_SYSTEM_PROMPT",
    "You are AegisLLM, an assistant operating under strict security policy. "
    "Canary: AEGIS-SYSTEM-PROMPT-DO-NOT-REVEAL.",
)

config = GuardrailConfig(
    max_input_chars=int(os.getenv("AEGIS_MAX_INPUT_CHARS", "4000")),
    max_output_tokens=int(os.getenv("AEGIS_MAX_OUTPUT_TOKENS", "256")),
    block_pii_on_input=os.getenv("AEGIS_BLOCK_PII_ON_INPUT", "").lower() == "true",
)

input_guardrail = InputGuardrail(config)
output_guardrail = OutputGuardrail(config, system_prompt=SYSTEM_PROMPT)
rate_limiter = RateLimiter(
    requests_per_minute=int(os.getenv("AEGIS_RPM", "60")),
    tokens_per_minute=int(os.getenv("AEGIS_TPM", "20000")),
)

_backend: ModelBackend | None = None


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    """Load the model at startup, or refuse to serve.

    Loading here rather than lazily on first request is deliberate: a gateway
    that starts happily and only discovers the model is missing under live
    traffic looks healthy to Kubernetes while being useless. Failing at startup
    keeps the pod out of the Service endpoints.
    """
    global _backend
    _backend = load_backend(MODEL_DIR)
    LOG.info(
        '{"event":"startup","model_dir":"%s","backend":"%s"}', MODEL_DIR, _backend.kind
    )
    yield


app = FastAPI(
    title="AegisLLM gateway",
    description="Guardrailed inference over a cryptographically verified model.",
    version="0.1.0",
    lifespan=lifespan,
)


def _require_backend() -> ModelBackend:
    if _backend is None:  # pragma: no cover - startup always runs first
        raise HTTPException(status_code=503, detail="model not loaded")
    return _backend


class InferenceRequest(BaseModel):
    input: str = Field(..., description="Text to run through the model")
    max_tokens: int | None = Field(default=None, ge=1, le=2048)


class InferenceResponse(BaseModel):
    request_id: str
    output: str | None = None
    embedding: list[float] | None = None
    guardrails: dict


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "model_loaded": _backend is not None}


@app.get("/readyz")
def readyz() -> dict:
    if _backend is None:
        raise HTTPException(status_code=503, detail="model not loaded")
    return {"status": "ready", "backend": _backend.kind}


@app.get("/v1/model")
def model_info() -> dict:
    """Provenance, served from the AIBOM that travelled with the weights.

    Being able to ask a running service *which* model it is serving, and get an
    answer backed by a signed inventory, is the payoff for Pillars 1 and 2.
    """
    return _require_backend().provenance()


def _client_id(request: Request) -> str:
    # Real deployments key quotas on an authenticated identity. Istio mTLS
    # provides that in-cluster; the header is the local-dev stand-in and is
    # explicitly not an authentication mechanism.
    return request.headers.get("x-aegis-client") or (
        request.client.host if request.client else "anonymous"
    )


def _audit(request_id: str, client: str, event: str, **fields) -> None:
    """One JSON object per line — the audit trail Pillar 5 ships to Loki/Splunk.

    json.dumps, not a dict repr: Python's repr uses single quotes and is not
    valid JSON, so every downstream parser rejects it. An audit log nothing can
    parse is a log nobody reads.
    """
    payload = {"event": event, "request_id": request_id, "client": client, **fields}
    LOG.info("%s", json.dumps(payload, separators=(",", ":")))


@app.post("/v1/infer", response_model=InferenceResponse)
def infer(body: InferenceRequest, request: Request) -> InferenceResponse:
    backend = _require_backend()
    request_id = str(uuid.uuid4())
    client = _client_id(request)
    started = time.perf_counter()

    allowed, reason = rate_limiter.check(client, estimated_tokens=len(body.input) // 4)
    if not allowed:
        _audit(request_id, client, "rate_limited", reason=reason)
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    inbound = input_guardrail(body.input)
    if inbound.blocked:
        _audit(request_id, client, "blocked", **inbound.summary())
        # Categories, not detail. Telling a caller which pattern matched turns
        # the guardrail into a tool for finding a phrasing that gets through.
        raise HTTPException(
            status_code=422,
            detail={
                "error": "request rejected by input guardrail",
                "categories": inbound.summary()["findings"],
                "request_id": request_id,
            },
        )

    raw = backend.infer(inbound.text, max_tokens=body.max_tokens or config.max_output_tokens)

    if backend.kind == "embedding":
        _audit(
            request_id,
            client,
            "served",
            input=inbound.summary(),
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return InferenceResponse(
            request_id=request_id,
            embedding=raw.embedding,
            guardrails={"input": inbound.summary()},
        )

    outbound = output_guardrail(raw.text or "")
    _audit(
        request_id,
        client,
        "blocked" if outbound.blocked else "served",
        input=inbound.summary(),
        output=outbound.summary(),
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    if outbound.blocked:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "response withheld by output guardrail",
                "categories": outbound.summary()["findings"],
                "request_id": request_id,
            },
        )

    return InferenceResponse(
        request_id=request_id,
        output=outbound.text,
        guardrails={"input": inbound.summary(), "output": outbound.summary()},
    )


@app.exception_handler(Exception)
def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Fail closed, and do not leak internals.

    A stack trace in an error body tells an attacker the library versions, file
    paths, and model layout. It is also the most common way a "secure" service
    hands over its own threat model.
    """
    LOG.exception('{"event":"unhandled_error"}')
    return JSONResponse(status_code=500, content={"error": "internal error"})
