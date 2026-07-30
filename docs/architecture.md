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
│  PILLAR 2: HARDENED CI/CD + ADMISSION GATE    ✅ built                        │
│    GitHub Actions ─▶ Trivy ─▶ cosign keyless ─▶ SLSA provenance ─▶ GHCR       │
│    Kyverno: refuse unsigned images, unpinned models, missing verifier         │
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

## Pillar 2 — design notes

### The hard problem: Kyverno cannot verify a model signature

This is the wrinkle worth understanding, because the obvious design does not work.

Kyverno's `verifyImages` extracts image references from the **pod spec** —
containers, initContainers, ephemeralContainers. A model published as an OCI
artifact is not a runnable image and never appears there. You can put the model
reference in an annotation, but Kyverno will not verify an annotation's
signature. Anyone claiming "Kyverno verifies my model signature from a pod
annotation" is describing something the tool does not do.

So enforcement is split, and it is worth being precise about what each half
proves:

| | Layer 1 — Kyverno, at admission | Layer 2 — verifier init container, at start-up |
|---|---|---|
| **Checks** | structure: digest-pinned, internal registry, verifier present, image signature valid | cryptography: manifest signature, then the model-signing bundle over the weight bytes |
| **Proves** | the pod is *shaped* so verification must happen | the weights are authentic and unmodified |
| **Fails by** | refusing admission | exiting non-zero, so the serving container never starts |

Neither is sufficient alone. Without Layer 1 a pod could simply omit the
verifier; without Layer 2 nothing would check a signature at all. The container
*image* signature check in Layer 1 **is** genuinely cryptographic — images do
appear in the pod spec — and it is what makes trusting the Layer 2 verifier
binary reasonable.

### Two signatures over the same model, deliberately

- **model-signing bundle** — covers the file bytes. Answers "are these the exact
  tensors that were scanned?" Checked when the model is loaded.
- **cosign signature on the OCI manifest** — answers "did we publish this?"
  Checkable from the manifest alone, without pulling gigabytes of weights.

The second exists because the first is unreadable to everything except this
pipeline. Kyverno, and the OCI ecosystem generally, speak cosign.

### Interoperability constraints found the hard way

Two version mismatches cost real debugging time and are worth recording, because
both fail in the same misleading direction — they look like a missing signature
when they are a protocol difference:

- **cosign v3 vs Kyverno 1.18.** cosign v3 publishes signatures as OCI 1.1
  referrers carrying a sigstore bundle. Kyverno 1.18 reads the legacy
  `sha256-<digest>.sig` tag, and its `cosignOCI11: true` option does not
  understand the new bundle artifact type either. `--registry-referrers-mode=legacy`
  does not restore the old behaviour. Container images are therefore signed with
  a pinned **cosign v2.4.3** (`make verifier-image` fetches it); model artifacts
  still use the system cosign, because only our own verifier reads those.
- **oras 1.2 vs 1.3.** `oras discover --format json` returns referrers under
  `manifests` in 1.2.x and `referrers` in 1.3.x. Reading only one key makes the
  verifier silently find no signature — which is indistinguishable from an
  unsigned artifact, so it fails closed *as though under attack*. The code
  accepts both keys.

### Registry naming

`localhost:5001` is the host-side view. In-cluster workloads must use
`aegis-registry:5000`, because inside a pod `localhost` is the pod itself — this
bit both Kyverno and the verifier init container. containerd carries a
`hosts.toml` for both names so either resolves to the same registry over plain
HTTP.

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
