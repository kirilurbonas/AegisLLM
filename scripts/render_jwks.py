#!/usr/bin/env python3
"""Inline the cluster's OIDC signing keys into the RequestAuthentication.

Istio can fetch a JWKS from a URL, but the Kubernetes API server requires
authentication on /openid/v1/jwks. The commonly-suggested fix is to bind
`system:service-account-issuer-discovery` to `system:unauthenticated`, which
opens cluster metadata to anonymous callers so that a config file can stay
static. Rendering the keys in at apply time avoids that trade entirely.

The keys are public. Re-run this if the cluster's signing keys are rotated —
`make istio-policies` does, every time.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

PLACEHOLDER = "AEGIS_CLUSTER_JWKS"


def cluster_jwks() -> str:
    result = subprocess.run(
        ["kubectl", "get", "--raw", "/openid/v1/jwks"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"✗ could not read the cluster JWKS:\n{result.stderr}", file=sys.stderr)
        raise SystemExit(1)
    # Compact, and validated as JSON before it goes anywhere near the cluster.
    return json.dumps(json.loads(result.stdout), separators=(",", ":"))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: render_jwks.py <request-authentication.yaml>", file=sys.stderr)
        return 2

    path = pathlib.Path(sys.argv[1])
    template = path.read_text()
    if PLACEHOLDER not in template:
        print(f"✗ {path} has no {PLACEHOLDER} placeholder", file=sys.stderr)
        return 1

    print(template.replace(PLACEHOLDER, cluster_jwks()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
