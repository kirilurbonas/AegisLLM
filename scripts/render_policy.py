#!/usr/bin/env python3
"""Inject the real cosign public key into the image-verification policy.

The policy is committed with a placeholder rather than a key, so the repo stays
fork-agnostic: your cluster verifies against *your* key, not a key checked into
someone else's GitHub. Rendering happens at apply time.
"""

from __future__ import annotations

import pathlib
import re
import sys

INDENT = " " * 22
PLACEHOLDER = re.compile(
    rf"{INDENT}-----BEGIN PUBLIC KEY-----\n.*?{INDENT}-----END PUBLIC KEY-----",
    re.DOTALL,
)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: render_policy.py <policy.yaml> <cosign.pub>", file=sys.stderr)
        return 2

    policy_path, key_path = (pathlib.Path(p) for p in sys.argv[1:3])
    if not key_path.exists():
        print(
            f"✗ {key_path} not found — run `make supply-chain` once to generate "
            "the signing keys, or point AEGIS_COSIGN_PUB at your own.",
            file=sys.stderr,
        )
        return 1

    key = key_path.read_text().strip()
    indented = "\n".join(INDENT + line for line in key.splitlines())
    rendered, count = PLACEHOLDER.subn(indented, policy_path.read_text())
    if count != 1:
        print(
            f"✗ expected exactly one key placeholder in {policy_path}, found {count}",
            file=sys.stderr,
        )
        return 1

    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
