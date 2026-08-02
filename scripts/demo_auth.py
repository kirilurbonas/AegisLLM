#!/usr/bin/env python3
"""Prove the gateway's front door: identity is required and cannot be forged.

Each case declares the status it expects and the script exits non-zero if reality
disagrees, so this is a test that happens to be readable rather than a scripted
screenshot. It runs from inside the mesh, because that is the only place a caller
can complete a STRICT mTLS handshake.

The regression it guards is concrete: before this workstream the gateway trusted
an `x-aegis-client` header, so anyone could pick an identity, dodge their quota,
and write whatever they liked into the audit log.
"""

from __future__ import annotations

import subprocess
import sys

NAMESPACE = "aegis"
CLIENT_POD = "aegis-test-client"
GATEWAY = "http://aegis-gateway.aegis.svc.cluster.local"
TOKEN_PATH = "/var/run/secrets/aegis/token"

BODY = '{"input":"hello there","max_tokens":4}'


def curl(args: str) -> str:
    """Run curl inside the client pod and return the HTTP status code."""
    command = (
        f"curl -s -o /dev/null -w '%{{http_code}}' -m 30 "
        f"-X POST {GATEWAY}/v1/infer "
        f"-H 'content-type: application/json' {args} -d '{BODY}'"
    )
    result = subprocess.run(
        ["kubectl", "-n", NAMESPACE, "exec", CLIENT_POD, "-c", "curl", "--", "sh", "-c", command],
        capture_output=True,
        text=True,
        check=False,
    )
    return (result.stdout or result.stderr).strip().splitlines()[-1] if (
        result.stdout or result.stderr
    ) else "000"


CASES = [
    (
        "no credentials at all",
        "",
        "403",
        "Istio AuthorizationPolicy refuses a request with no validated principal",
    ),
    (
        "forged identity header",
        "-H 'x-aegis-principal: system:serviceaccount:aegis:admin'",
        "403",
        "the header the app reads is not one a caller can set — the proxy owns it",
    ),
    (
        "the old spoofable header",
        "-H 'x-aegis-client: admin'",
        "403",
        "the pre-Vault vulnerability: setting this used to be enough",
    ),
    (
        "garbage bearer token",
        "-H 'Authorization: Bearer not-a-real-token'",
        "401",
        "an unverifiable token is rejected by the mesh, not by the application",
    ),
    (
        "valid projected SA token",
        f"-H \"Authorization: Bearer $(cat {TOKEN_PATH})\"",
        "200",
        "a real, audience-scoped, short-lived identity is served",
    ),
]


def main() -> int:
    print(f"Calling {GATEWAY} from inside the mesh as pod/{CLIENT_POD}\n")
    failures = 0
    for label, args, expected, note in CASES:
        status = curl(args)
        ok = status == expected
        failures += not ok
        print(f"{'✓' if ok else '✗'} {label:<26} HTTP {status} (expected {expected})")
        print(f"    {note}")

    print()
    if failures:
        print(f"✗ {failures} case(s) did not behave as specified")
        return 1
    print("✓ identity is required, and cannot be supplied by the caller")
    return 0


if __name__ == "__main__":
    sys.exit(main())
