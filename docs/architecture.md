# AegisLLM architecture

Five control planes over one pipeline. Pillars 0 and 1 are built; the rest are
scaffolded and planned.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  PILLAR 1: SECURE MODEL SUPPLY CHAIN          ✅ built                        │
│    HuggingFace ─▶ modelscan/picklescan ─▶ safetensors ─▶ AIBOM (CycloneDX)    │
│                ─▶ sigstore model-signing ─▶ internal OCI registry (Zot)       │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  PILLAR 2: HARDENED CI/CD + GITOPS            🚧 planned                      │
│    GitHub Actions ─▶ SLSA provenance ─▶ Trivy ─▶ cosign ─▶ ArgoCD ─▶ K8s      │
│    Kyverno admission: refuse any unsigned image OR unsigned model             │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  PILLAR 3: RUNTIME SECURITY GATEWAY           🚧 planned                      │
│    FastAPI ─▶ input guardrails ─▶ vLLM/Ollama ─▶ output guardrails            │
│    mTLS (Istio) · RBAC · Vault secrets · rate & token quotas                  │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  PILLAR 4: CONTINUOUS AI RED-TEAMING          🚧 planned                      │
│    garak + promptfoo in CI ─▶ OWASP LLM Top 10 / MITRE ATLAS scorecard        │
│    Pipeline fails on security regression                                      │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  PILLAR 5: OBSERVABILITY & GOVERNANCE         🚧 planned                      │
│    Grafana · inference audit log · NIST AI RMF / ISO 42001 control matrix     │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Pillar 0 — foundation (built)

Terraform stands up three things on the local machine:

| Component | Why |
|---|---|
| `kind` cluster | Free, fast, disposable. Cloud is a screenshot exercise, not a dependency. |
| Zot OCI registry | The air-gap boundary. One container, no database, and — critically — it implements the OCI **referrers** API, which is how signatures ride alongside artifacts. |
| ArgoCD | The only actor permitted to change cluster state. |

containerd on the kind node is given a `hosts.toml` mirror entry so an in-cluster
reference to `localhost:5001/...` resolves to the Zot container over the shared
`kind` docker network, rather than escaping to a public registry.

## Pillar 1 — design notes

The stages are separate CLI subcommands rather than one script, for three reasons:
each can be demoed in isolation, each writes an independently auditable JSON
report, and CI can run them as distinct jobs with distinct failure semantics.

**Why two scanners.** They cover different things and neither is sufficient.
`modelscan` parses the PyTorch zip container and grades unsafe operators by
severity. `picklescan` reads raw pickle opcodes. A bare `.bin` pickle with no
torch magic number is *skipped* by modelscan — reported as zero issues, which
reads exactly like "clean" — and caught by picklescan. Running one alone leaves
a hole. Files that no scanner could parse are recorded as coverage gaps rather
than silently counted as passes.

**Why convert, having already scanned.** Scanning is detection and detection is
never complete. safetensors is a flat header-plus-bytes format with no opcode
stream, so conversion *eliminates* the deserialization attack surface instead of
searching it. Detection tells you about the payloads you know; conversion removes
the ones you don't. Conversion is only trustworthy if faithful, so every tensor
is compared for equality against the original before the pickle is discarded.

**Why the AIBOM sits inside the signature envelope.** `signing` covers the whole
secured directory, and the AIBOM lives in it. An inventory that can be edited
independently of the artifact it describes is worthless; sealing them together
means the claim and the thing claimed cannot drift apart.

**Why two signing modes.** Sigstore keyless signing gives excellent provenance —
OIDC identity, public transparency log, no long-lived key to leak — but it needs
a browser and internet access. Pillar 5 promises an air-gapped run and CI has no
browser, so a keyed elliptic-curve path exists from the start. Retrofitting an
offline path after building everything around keyless is a well-known way to get
stuck; the default here is `key`, with `--mode sigstore` for the public demo.

**Why the signature is an OCI referrer.** Attaching it to the manifest instead of
baking it in means a verifier can fetch and check it independently, without
pulling gigabytes of weights first. That is precisely the shape a Kyverno
admission policy needs in Pillar 2.

## Data flow

```
artifacts/
├── staging/<model>/    quarantine — untrusted, never served
├── secured/<model>/    safetensors + AIBOM — the signed unit
├── signed/<model>/     model.sig
├── pulled/<model>/     what a consumer gets back from the registry
└── reports/<model>/    ingest|scan|convert|aibom|sign|push|verify .json
```

`artifacts/` is gitignored: it is reproducible output, and staging holds
deliberately untrusted files.
