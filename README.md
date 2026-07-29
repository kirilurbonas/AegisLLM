# AegisLLM

**A GitOps-driven, air-gap-capable platform that takes an untrusted open-weights model from Hugging Face and turns it into a signed, scanned, policy-gated, guardrailed, continuously red-teamed production LLM service on Kubernetes.**

The software supply chain got secured over the last decade. The *model* supply chain did not. A Hugging Face checkpoint is untrusted third-party code — a classic `pickle`-based PyTorch file executes arbitrary code the moment you load it. AegisLLM treats every model exactly like an untrusted dependency: scan it, convert it to a non-executable format, inventory it, sign it, publish it to an internal registry, and refuse to run anything that can't prove its pedigree.

## Status

| Pillar | Scope | State |
|---|---|---|
| 1. Secure model supply chain | ingest → scan → safetensors → AIBOM → sign → OCI registry → verify | ✅ implemented |
| 0. Foundation | Terraform `kind` cluster, Zot registry, ArgoCD GitOps | ✅ implemented |
| 2. Hardened CI/CD + Kyverno admission gate | | 🚧 planned |
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

## Threat coverage

| OWASP LLM Top 10 (2025) | Control | Pillar |
|---|---|---|
| LLM03 Supply Chain | model scanning, signing, AIBOM, signed OCI registry | 1 ✅ |
| LLM04 Data & Model Poisoning | provenance verification, safetensors, revision pinning | 1 ✅ |
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
gateway/         Pillar 3 — FastAPI inference gateway
redteam/         Pillar 4 — garak / promptfoo suites
```
