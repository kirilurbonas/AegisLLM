"""Authentication: the gateway must not serve a caller it cannot identify.

The regression these guard against is the one this workstream existed to fix —
the gateway used to accept `x-aegis-client` from anyone, so quotas were
bypassable and the audit log recorded whatever the caller claimed.
"""

from __future__ import annotations

import json
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from gateway import app as app_module
from gateway import auth
from gateway.limits import RateLimiter
from gateway.model import InferenceOutput, ModelBackend

MESH = {"x-aegis-principal": "system:serviceaccount:aegis:caller-one"}
OTHER_MESH = {"x-aegis-principal": "system:serviceaccount:aegis:caller-two"}


class StubBackend(ModelBackend):
    kind = "generative"

    def __init__(self) -> None:
        self._aibom = None

    def infer(self, text: str, max_tokens: int) -> InferenceOutput:
        return InferenceOutput(text="ok")


@pytest.fixture(autouse=True)
def backend(monkeypatch):
    monkeypatch.setattr(app_module, "_backend", StubBackend())
    monkeypatch.setattr(
        app_module,
        "rate_limiter",
        RateLimiter(requests_per_minute=1000, tokens_per_minute=10**7),
    )
    # Default posture is auth-required; individual tests opt out explicitly.
    monkeypatch.setenv("AEGIS_REQUIRE_AUTH", "true")
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app_module.app)


def test_unauthenticated_inference_is_refused(client):
    response = client.post("/v1/infer", json={"input": "hello"})

    assert response.status_code == 401


def test_unauthenticated_model_info_is_refused(client):
    """Which model is running, at which revision, is not public reconnaissance."""
    assert client.get("/v1/model").status_code == 401


def test_health_probes_stay_open(client):
    """Kubelet probes carry no token; a gateway that cannot be probed never
    becomes Ready. The exemption is narrow and touches no model data."""
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_authenticated_request_is_served(client):
    response = client.post("/v1/infer", json={"input": "hello"}, headers=MESH)

    assert response.status_code == 200


def test_the_old_spoofable_header_grants_nothing(client):
    """`x-aegis-client` was the vulnerability. It must now be inert."""
    response = client.post(
        "/v1/infer", json={"input": "hello"}, headers={"x-aegis-client": "admin"}
    )

    assert response.status_code == 401


def test_spoofed_client_header_cannot_change_the_audited_identity(client, caplog):
    with caplog.at_level("INFO", logger="aegis.gateway"):
        client.post(
            "/v1/infer",
            json={"input": "hello"},
            headers={**MESH, "x-aegis-client": "someone-else"},
        )

    audited = [json.loads(r.getMessage()) for r in caplog.records]
    served = [r for r in audited if r.get("event") == "served"]
    assert served, "the request should have been audited"
    assert served[0]["client"] == MESH["x-aegis-principal"]
    assert "someone-else" not in json.dumps(audited)


def test_quota_is_keyed_on_the_verified_principal(monkeypatch, client):
    """Two identities must not share a quota, and one must not be able to escape
    its own by relabelling itself."""
    monkeypatch.setattr(
        app_module,
        "rate_limiter",
        RateLimiter(requests_per_minute=1, tokens_per_minute=10**6),
    )

    first = client.post("/v1/infer", json={"input": "a"}, headers=MESH)
    repeat = client.post("/v1/infer", json={"input": "a"}, headers=MESH)
    different = client.post("/v1/infer", json={"input": "a"}, headers=OTHER_MESH)

    assert first.status_code == 200
    assert repeat.status_code == 429, "the same principal must not exceed its quota"
    assert different.status_code == 200, "a separate identity has its own quota"


def test_exhausted_principal_cannot_reset_its_quota_with_a_header(monkeypatch, client):
    monkeypatch.setattr(
        app_module,
        "rate_limiter",
        RateLimiter(requests_per_minute=1, tokens_per_minute=10**6),
    )
    client.post("/v1/infer", json={"input": "a"}, headers=MESH)

    evasion = client.post(
        "/v1/infer",
        json={"input": "a"},
        headers={**MESH, "x-aegis-client": "fresh-identity"},
    )

    assert evasion.status_code == 429


# --------------------------------------------------------------------------
# The development escape hatch must not be usable in a cluster
# --------------------------------------------------------------------------

def test_auth_can_be_disabled_for_local_development(monkeypatch, client):
    monkeypatch.setenv("AEGIS_REQUIRE_AUTH", "false")

    assert client.post("/v1/infer", json={"input": "hello"}).status_code == 200


def test_disabling_auth_is_refused_when_running_in_a_cluster(monkeypatch, client):
    """A misconfigured deployment silently serving unauthenticated traffic is
    exactly the failure this module exists to prevent."""
    monkeypatch.setenv("AEGIS_REQUIRE_AUTH", "false")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")

    assert client.post("/v1/infer", json={"input": "hello"}).status_code == 401


def test_principal_resolution_never_falls_back_to_client_input(monkeypatch):
    """Unit-level: the resolver reads one header and no other."""
    monkeypatch.setenv("AEGIS_REQUIRE_AUTH", "true")

    class FakeRequest:
        headers: ClassVar[dict[str, str]] = {
            "x-aegis-client": "attacker",
            "authorization": "Bearer forged",
        }

    with pytest.raises(auth.AuthError):
        auth.principal_from(FakeRequest())
