# AegisLLM

**A GitOps-driven, air-gap-capable platform that takes an untrusted open-weights model from Hugging Face and turns it into a signed, scanned, policy-gated, guardrailed, continuously red-teamed production LLM service on Kubernetes.**

The software supply chain got secured over the last decade. The *model* supply chain did not. A Hugging Face checkpoint is untrusted third-party code — a classic `pickle`-based PyTorch file executes arbitrary code the moment you load it. AegisLLM treats every model exactly like an untrusted dependency: scan it, convert it to a non-executable format, inventory it, sign it, publish it to an internal registry, and refuse to run anything that can't prove its pedigree.

## Status

| Pillar | Scope | State |
|---|---|---|
| 1. Secure model supply chain | ingest → scan → safetensors → AIBOM → sign → OCI registry → verify | ✅ implemented |
| 0. Foundation | Terraform `kind` cluster, Zot registry, ArgoCD GitOps | ✅ implemented |
| 2. Hardened CI/CD + admission gate | Trivy → cosign → SLSA provenance; Kyverno refuses unsigned images and unverified models | ✅ implemented |
| 3. Runtime security gateway | FastAPI + input/output guardrails, quotas, egress lockdown, audit trail | ✅ implemented |
| 4. Continuous AI red-teaming (garak / promptfoo) | | 🚧 planned |
| 5. Observability & governance | | 🚧 planned |
| **Identity & secrets** | Istio STRICT mTLS + JWT auth; signing keys in Vault (Transit, non-exportable) | ✅ implemented |

See [docs/architecture.md](docs/architecture.md) for the full five-pillar design and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the OWASP LLM Top 10 mapping.

## Quickstart

Requires Docker Desktop running, plus `uv`, `kind`, `kubectl`, `helm`, `terraform`, `cosign`, `oras`.

```bash
make check          # preflight: docker daemon + required binaries
make tools          # brew install anything missing
make install        # uv sync

make supply-chain   # Pillar 1 end-to-end, signed model in the local registry
make demo-tamper    # flip a byte in the weights — verification must FAIL

make cluster        # terraform: kind cluster + Zot registry + ArgoCD
eval $(make kubeconfig)
make gitops         # apply the app-of-apps; hello service reconciles
make clean-cluster  # tear it all down
```

`make gitops` needs a reachable git URL — ArgoCD reconciles from git, not from
your working tree. It uses your `origin` remote, so push the repo first, or pass
one explicitly: `make gitops AEGIS_REPO_URL=https://github.com/<you>/aegisllm.git`.

`make supply-chain-offline` runs the pipeline with no registry and no Docker at
all, stopping after signing — handy in CI and on a plane.

## Pillar 1: what actually happens

```
huggingface.co
      │  aegis ingest      pinned to a commit SHA, never a branch
      ▼
 artifacts/staging/
      │  aegis scan        modelscan + picklescan; non-zero exit on CRITICAL
      ▼
      │  aegis convert     torch .bin → .safetensors, tensor-equivalence checked
      ▼
      │  aegis aibom       CycloneDX 1.6 ML-BOM: license, source, revision, hashes
      ▼
      │  aegis sign        sigstore keyless (demo) or keyed cosign (CI / air-gap)
      ▼
 localhost:5001/models/…   aegis push — weights + AIBOM + signature bundle as one
      │                    OCI artifact; the AIBOM attached as an OCI referrer
      ▼
      │  aegis verify      pull, re-hash, verify signature. Tamper ⇒ exit 1.
```

Nothing at runtime ever calls out to Hugging Face. The registry is the air-gapped mirror.

The gate is not decorative: `tests/test_scan.py` builds a genuinely malicious pickle whose
`__reduce__` invokes `os.system`, and asserts the scanner flags it and the pipeline refuses
to continue.

## Pillar 2: nothing unverified runs

```bash
make cluster && eval $(make kubeconfig)
make supply-chain          # publish a signed model
make verifier-image        # build + sign the verifier init container
make kyverno keys-secret   # install Kyverno and the AegisLLM policies
make demo-admission        # the gate, proven
```

`make demo-admission` output:

```
── compliant pod (must be ADMITTED and reach Running) ──
→ the serving container sees:
serving verified model from /models:
aibom.cdx.json
model.safetensors
── unpinned (must be REFUSED) ──
  ✓ blocked by rule: model-must-be-digest-pinned
── external (must be REFUSED) ──
  ✓ blocked by rule: model-must-come-from-the-internal-registry
── no-verifier (must be REFUSED) ──
  ✓ blocked by rule: verifier-init-container-must-be-present
```

The policies also have offline unit tests — `make test-policies` asserts, per
rule, which example pods must pass and which must fail. Weakening a rule turns
CI red. (Verified by weakening one on purpose: the suite caught it.) An admission
gate that quietly stops enforcing is worse than none, because everyone goes on
assuming it works.

**The honest version of how this works**, because the obvious design doesn't:
Kyverno's `verifyImages` reads image references out of the *pod spec*, and a
model published as an OCI artifact never appears there. Kyverno cannot verify a
model signature from an annotation, and anyone who says it can is describing
something the tool does not do. So enforcement is split — Kyverno proves the pod
is **shaped** so verification must happen (digest-pinned, internal registry,
verifier present, image signature valid), and the verifier init container does
the **cryptography** and fails closed. Neither half is sufficient alone.
[docs/architecture.md](docs/architecture.md) explains why the split is forced
rather than chosen, and records two version mismatches (cosign v3 ↔ Kyverno 1.18,
oras 1.2 ↔ 1.3) that both fail in the misleading direction of looking like a
missing signature.

## Pillar 3: the only door to the model

```bash
AEGIS_MODEL_ID=sshleifer/tiny-gpt2 uv run aegis all   # sign a generative model
make gateway-image deploy-gateway                     # build, sign, deploy
make demo-guardrails                                  # prove the guardrails
```

```
Serving a model this service can prove the origin of:
  sshleifer/tiny-gpt2
  revision     5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be
  scan verdict PASS
  weights      safetensors

✓ clean prompt               HTTP 200  — ordinary traffic is served
✓ prompt injection           HTTP 422  — LLM01 instruction override refused
✓ system prompt extraction   HTTP 422  — LLM07 extraction attempt refused
✓ role injection             HTTP 422  — LLM01 chat-template injection refused
✓ credential in prompt       HTTP 422  — LLM02 secret never reaches model or log
✓ PII in prompt              HTTP 200  — LLM02 redacted, not refused: it still works
✓ oversized prompt           HTTP 422  — LLM10 unbounded input refused
```

**The guardrails are a weak control and the repo says so.** Pattern matching
catches known phrasings and casual attempts; paraphrase, encoding, translation or
multi-turn splitting will get past it. Anyone shipping a regex list as "prompt
injection protection" is building security theatre.

What actually bounds the damage is architectural, and does not degrade as the
attacker gets more creative — the gateway has **no internet egress** (verified: a
public-internet connect from inside the pod times out while the internal registry
resolves), **no tools, no credentials, no registry client**, and mounts the
weights **read-only**. A successful injection has nothing to reach for. That is
OWASP LLM06 by design rather than detection.

Three smaller decisions worth noting:

- **Input is rejected, output is redacted.** There is no safe way to sanitise an
  adversarial prompt. But a leaked email in an otherwise useful answer should be
  masked, not discarded — so PII is redacted and the request still works. Secrets
  are the exception and block outright.
- **False positives are a security property.** The suite asserts ordinary text
  ("please ignore the noise in the data") is *not* blocked, and the card detector
  runs a Luhn check. A guardrail that cries wolf gets switched off.
- **Failures are opaque.** Rejections return categories, never the matched
  pattern — otherwise the guardrail is a free oracle for tuning an attack. The
  audit log follows the same rule and never records prompt text.

The demo model is an untrained stub that emits gibberish. That is deliberate: the
security scaffolding is the product, and guardrails act on text whether or not it
is coherent.

## Identity & secrets: closing the two production gaps

Pillars 1–3 were demonstrably secure about *models* while being naive about
*callers* and *keys*. Two findings from auditing the repo against a production
bar, and what was done:

**1. The gateway had no authentication.** It read an `x-aegis-client` header and
believed it — so quotas were bypassable by changing a string, and the audit log
recorded whatever the caller claimed. Now:

```bash
make istio          # STRICT mTLS + JWT validation + deny-by-default authorization
make demo-auth
```

```
✓ no credentials at all      HTTP 403  — no validated principal, refused by policy
✓ forged identity header     HTTP 403  — the proxy owns that header, not the caller
✓ the old spoofable header   HTTP 403  — x-aegis-client is now inert
✓ garbage bearer token       HTTP 401  — rejected by the mesh, not the application
✓ valid projected SA token   HTTP 200  — audience-scoped, short-lived, real
```

Identity comes from **projected Kubernetes ServiceAccount tokens** — real OIDC
JWTs, audience-scoped and kubelet-rotated — so service-to-service auth needs no
extra IdP. Istio validates signature, issuer, expiry and audience, then writes the
subject into a header it overwrites on every request. The app reads only that
header and fails closed; the dev escape hatch refuses to work in-cluster, because
a deployment that silently serves unauthenticated traffic is the exact failure
being prevented.

**2. Signing keys were files on disk with empty passphrases.** Now the cosign key
is a Vault **Transit** key created *non-exportable* — signing is an API call and
the private half cannot be read out by anyone, including an operator with the root
token. The whole supply chain was re-run with the local key files deleted to prove
it.

`model_signing` has no KMS backend (elliptic-key, certificate, PKCS#11 and
sigstore signers only), so its key lives in Vault kv-v2 and is materialised to
tmpfs only for the moments a signature is produced. That is a real improvement and
**not** equivalent to Transit — [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) keeps
them separate rather than blurring both into "keys are in Vault".

### A policy bug the mesh exposed

Installing Istio broke the admission gate, and the reason is worth keeping. The
rule said "a verifier init container must be present" as a Kyverno list pattern —
but Kyverno applies list patterns to *every* element, so the moment Istio injected
its proxy as a second init container, a fully compliant gateway was rejected
because `istio-proxy` is not named `aegis-verify`. The policy had silently assumed
nothing would ever add an init container.

It is now a count-based `deny` selecting by name, plus a separate rule asserting
the verifier image is the real one (presence alone would be satisfied by a busybox
doing nothing). Both cases are locked in as policy tests.

## Threat coverage

| OWASP LLM Top 10 (2025) | Control | Pillar |
|---|---|---|
| LLM03 Supply Chain | model scanning, signing, AIBOM, signed OCI registry, admission gate | 1, 2 ✅ |
| LLM04 Data & Model Poisoning | provenance verification, safetensors, revision pinning, admission gate | 1, 2 ✅ |
| LLM01 Prompt Injection | input guardrail (weak) + egress lockdown bounding impact | 3 ⚠️ |
| LLM02 Sensitive Info Disclosure | secret/PII detection both ways, PII-free audit log | 3 ✅ |
| LLM05 Improper Output Handling | typed schema, output guardrail, no partial content | 3 ✅ |
| LLM06 Excessive Agency | no egress, no tools, no credentials, read-only weights | 3 ✅ |
| LLM07 System Prompt Leakage | Secret-supplied prompt + canary detection | 3 ⚠️ |
| LLM09 Misinformation | grounding + promptfoo assertions | 4 🚧 |
| LLM10 Unbounded Consumption | request + token quotas, input and generation caps | 3 ✅ |

## Layout

```
supplychain/     Pillar 1 — the model supply chain CLI (`aegis`)
infra/terraform/ kind cluster, Zot OCI registry, ArgoCD
gitops/          app-of-apps + workloads reconciled by ArgoCD
policies/        Pillar 2 — Kyverno admission policies
examples/        compliant and deliberately non-compliant model-serving pods
.github/         CI (lint, test, scan gate) and release (Trivy, cosign, SLSA)
gateway/         Pillar 3 — FastAPI gateway, guardrails, quotas
redteam/         Pillar 4 — garak / promptfoo suites
```
