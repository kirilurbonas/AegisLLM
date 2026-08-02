"""Caller identity for the gateway.

The gateway previously read an `x-aegis-client` header and treated it as who the
caller was. That was not authentication: anyone could set it, so quotas were
bypassable by changing a string and the audit log recorded whatever the caller
felt like claiming.

Identity now comes from a JWT that Istio validated before the request reached
this process. The important property is not that a header is read — it is
*which* header, and who can write it:

* Istio's `RequestAuthentication` verifies the token's signature, issuer, expiry
  and audience, then writes the `sub` claim into `x-aegis-principal`.
* The proxy **overwrites** that header on every request, so a value supplied by
  a client is discarded before the application sees it.
* An `AuthorizationPolicy` denies any request without a validated principal, so
  in a correctly-deployed cluster an unauthenticated request never arrives here.

This module is therefore the second line, not the first, and it is written to
fail closed anyway: no principal means no service. Defence in depth matters here
because the trust in that header is entirely a property of the deployment — run
this pod outside the mesh and the header becomes attacker-controlled again.
`AEGIS_REQUIRE_AUTH=false` exists for local development and is refused when the
process looks like it is running in a cluster.
"""

from __future__ import annotations

import dataclasses
import os

from fastapi import HTTPException, Request

PRINCIPAL_HEADER = "x-aegis-principal"

# Set by Istio on every inbound request; its presence is a reasonable signal that
# a sidecar is in front of us. It is a heuristic used only to refuse an unsafe
# *configuration*, never to make an authorization decision.
MESH_HEADER = "x-envoy-peer-metadata"


@dataclasses.dataclass(frozen=True)
class Principal:
    """An authenticated caller."""

    subject: str
    #: Where the identity came from — recorded in the audit log so an operator
    #: can tell a mesh-verified request from a dev-mode one at a glance.
    source: str

    @property
    def quota_key(self) -> str:
        return self.subject


def require_auth_enabled() -> bool:
    return os.getenv("AEGIS_REQUIRE_AUTH", "true").lower() != "false"


def running_in_cluster() -> bool:
    return bool(os.getenv("KUBERNETES_SERVICE_HOST"))


class AuthError(HTTPException):
    def __init__(self, detail: str) -> None:
        # 401, not 403: the caller supplied no usable identity at all. The body
        # carries no hint about what would have been accepted.
        super().__init__(status_code=401, detail={"error": detail})


def principal_from(request: Request) -> Principal:
    """Resolve the caller, or refuse the request.

    Never falls back to a client-supplied identity. The old `x-aegis-client`
    header is ignored entirely — it is not consulted, not logged as identity, and
    setting it has no effect on quotas.
    """
    subject = request.headers.get(PRINCIPAL_HEADER, "").strip()
    if subject:
        return Principal(subject=subject, source="mesh-jwt")

    if require_auth_enabled():
        raise AuthError("unauthenticated")

    # Development escape hatch. Refused in-cluster, because a misconfigured
    # deployment that silently serves unauthenticated traffic is precisely the
    # failure this module exists to prevent.
    if running_in_cluster():
        raise AuthError("unauthenticated")

    return Principal(subject="local-dev", source="auth-disabled")
