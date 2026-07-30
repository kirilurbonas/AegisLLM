# AegisLLM

**A GitOps-driven, air-gap-capable platform that takes an untrusted open-weights model from Hugging Face and turns it into a signed, scanned, policy-gated, guardrailed, continuously red-teamed production LLM service on Kubernetes.**

The software supply chain got secured over the last decade. The *model* supply chain did not. A Hugging Face checkpoint is untrusted third-party code — a classic `pickle`-based PyTorch file executes arbitrary code the moment you load it. AegisLLM treats every model exactly like an untrusted dependency: scan it, convert it to a non-executable format, inventory it, sign it, publish it to an internal registry, and refuse to run anything that can't prove its pedigree.

## Status

| Pillar | Scope | State |
|---|---|---|
| 1. Secure model supply chain | ingest → scan → safetensors → AIBOM → sign → OCI registry → verify | ✅ implemented |
| 0. Foundation | Terraform `kind` cluster, Zot registry, ArgoCD GitOps | ✅ implemented |
| 2. Hardened CI/CD + admission gate | Trivy → cosign → SLSA provenance; Kyverno refuses unsigned images and unverified models | ✅ implemented |
| 3. Runtime security gateway (FastAPI + guardrails) | | 🚧 planned |
| 4. Continuous AI red-teaming (garak / promptfoo) | | 🚧 planned |
| 5. Observability & governance | | 🚧 planned |

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
pytorch_model.safetensors
── unpinned (must be REFUSED) ──
  ✓ blocked by rule: model-must-be-digest-pinned
── external (must be REFUSED) ──
  ✓ blocked by rule: model-must-come-from-the-internal-registry
── no-verifier (must be REFUSED) ──
  ✓ blocked by rule: verifier-init-container-must-be-present
```

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

## Threat coverage

| OWASP LLM Top 10 (2025) | Control | Pillar |
|---|---|---|
| LLM03 Supply Chain | model scanning, signing, AIBOM, signed OCI registry, admission gate | 1, 2 ✅ |
| LLM04 Data & Model Poisoning | provenance verification, safetensors, revision pinning, admission gate | 1, 2 ✅ |
| LLM01 Prompt Injection | input guardrails + red-team gate | 3, 4 🚧 |
| LLM02 Sensitive Info Disclosure | output PII/secret scanning + audit logging | 3, 5 🚧 |
| LLM05 Improper Output Handling | output guardrails, schema enforcement | 3 🚧 |
| LLM06 Excessive Agency | scoped RBAC, least privilege | 3 🚧 |
| LLM07 System Prompt Leakage | prompt isolation + red-team probes | 3, 4 🚧 |
| LLM09 Misinformation | grounding + promptfoo assertions | 4 🚧 |
| LLM10 Unbounded Consumption | rate/token quotas + cost dashboards | 3, 5 🚧 |

## Layout

```
supplychain/     Pillar 1 — the model supply chain CLI (`aegis`)
infra/terraform/ kind cluster, Zot OCI registry, ArgoCD
gitops/          app-of-apps + workloads reconciled by ArgoCD
policies/        Pillar 2 — Kyverno admission policies
examples/        compliant and deliberately non-compliant model-serving pods
.github/         CI (lint, test, scan gate) and release (Trivy, cosign, SLSA)
gateway/         Pillar 3 — FastAPI inference gateway
redteam/         Pillar 4 — garak / promptfoo suites
```
