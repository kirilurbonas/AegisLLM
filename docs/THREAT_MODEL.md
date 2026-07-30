# Threat model

Scope of this document: the model supply chain (Pillar 1), the platform
foundation (Pillar 0), and the CI/CD and admission gate (Pillar 2) — the parts
that exist. Runtime threats are listed
with their planned controls and marked as such — an unbuilt control is not a
mitigation.

## Assets

| Asset | Why an attacker wants it |
|---|---|
| Model weights | Theft (IP), or replacement with a backdoored equivalent |
| The signing key | Forge provenance for any model — the keys to the kingdom |
| The internal registry | Single point of distribution to every workload |
| The GitOps repo | Desired cluster state; whoever writes it, runs it |
| Inference traffic | Prompts and outputs may contain regulated data |

## Trust boundaries

```
   UNTRUSTED                  │  QUARANTINE   │        TRUSTED
 ──────────────────────────── │ ───────────── │ ─────────────────────
 huggingface.co               │ artifacts/    │ secured/ · registry
 model authors                │  staging/     │ signed artifacts
 arbitrary uploaded weights   │               │ the cluster
                              │               │
        scan + convert gate ──┘               └── signature verification
```

The staging directory is the quarantine: files there are assumed hostile.
Crossing into `secured/` requires passing the scan gate and being rewritten into
a non-executable format. Crossing into the cluster requires a valid signature.

## Threats and controls

### T1 — Malicious pickle in a model checkpoint (**mitigated**)
A `pickle`-serialized checkpoint executes arbitrary code on load: `__reduce__`
names any callable and `torch.load` calls it. This is actively exploited against
public model hubs.

*Controls:* `modelscan` + `picklescan` gate, blocking on CRITICAL/HIGH; conversion
to safetensors removes the execution surface entirely; `torch.load(weights_only=True)`
at the single moment the pipeline must open an untrusted pickle.
*Evidence:* `tests/test_scan.py` builds a real `os.system` payload and asserts the
gate blocks it and conversion refuses to run.

### T2 — Model substitution / typosquatting (**mitigated**)
An attacker serves different weights than the ones reviewed — by editing a branch,
publishing a lookalike repo, or intercepting the download.

*Controls:* revision pinning to an immutable commit SHA, recorded in the AIBOM;
SHA-256 manifest of every shipped file; signature over the whole secured directory.
*Evidence:* `test_tampered_weights_fail_verification` — one flipped byte is rejected.

### T3 — Tampering in transit or at rest in the registry (**mitigated**)
*Controls:* signature verification on pull; the artifact is rejected outright if
no signature referrer is attached.
*Evidence:* `make demo-tamper`.

### T4 — Inventory forgery (**mitigated**)
An accurate-looking AIBOM describing weights that were swapped out.
*Controls:* the AIBOM is inside the signed directory, so editing it breaks the
signature. *Evidence:* `test_tampered_aibom_fails_verification`.

### T5 — Forged signature from a foreign key (**mitigated**)
*Controls:* verification pins the expected public key (`key` mode) or the OIDC
identity and issuer (`sigstore` mode). A technically-valid signature by the wrong
signer is still a rejection. *Evidence:* `test_verification_fails_against_a_foreign_key`.

### T6 — Scanner blind spot (**partially mitigated**)
A weights file that no scanner can parse reports as zero issues, which is
indistinguishable from clean.
*Controls:* two scanners with different parsers; files neither could read are
recorded as coverage gaps in `scan.json`; alternate-runtime exports the pipeline
cannot secure (OpenVINO, ONNX, TF) are not ingested at all.
*Residual risk:* a novel format that parses cleanly but hides a payload. Detection
is inherently incomplete — this is why conversion, not scanning, is the primary
control.

### T7 — Signing key compromise (**partially mitigated**)
*Controls:* the key is gitignored, generated with 0600 permissions, and never
leaves the machine. `sigstore` mode removes the long-lived key entirely.
*Residual risk:* in `key` mode the key sits on the build host. Production would
move this to Vault or a KMS/HSM, or use sigstore keyless with workload identity.

### T8 — Unsigned or substituted model reaching the cluster (**mitigated**)
A human applies a manifest that mounts arbitrary weights, or points a serving pod
at a model nobody scanned.

*Controls, in two layers:*
- **Kyverno at admission** — the model reference must be digest-pinned and from
  the internal registry; the `aegis-verify` init container must be present; and
  every aegis-built image must carry a valid cosign signature.
- **The verifier init container at start-up** — cosign-verifies the OCI manifest,
  then verifies the model-signing bundle over the actual bytes. Exits non-zero on
  any failure, so the serving container never runs.

*Evidence:* `make demo-admission` — a compliant pod reaches Running with verified
weights; a tag-referenced model, a Hugging Face-sourced model, and a pod with no
verifier are each refused, with the failing rule named.

*Residual risk:* Kyverno cannot itself verify the model signature — an OCI model
artifact never appears in the pod spec, so `verifyImages` cannot reach it. Layer 1
proves the pod is *shaped* so that Layer 2 must run; Layer 2 does the
cryptography. See docs/architecture.md for why this split is forced rather than
chosen.

### T8b — Tampering with the verifier itself (**partially mitigated**)
If an attacker can substitute the verifier image, every downstream guarantee
collapses.

*Controls:* the verifier image is cosign-signed and Kyverno verifies that
signature at admission — this check *is* cryptographic, because images do appear
in the pod spec. The image runs unprivileged with a read-only root filesystem and
all capabilities dropped, and carries neither torch nor modelscan.

*Residual risk:* the policy matches the init container by name and image glob. A
cluster-admin who can edit ClusterPolicies can remove the gate entirely; Kyverno
RBAC is the control there, and it is out of scope for this build.

### T9 — Prompt injection, data leakage, unbounded consumption (**planned — Pillars 3–4**)
No inference path exists yet, so these are out of scope for the current build.

## OWASP LLM Top 10 (2025) coverage

| Risk | Status | Control |
|---|---|---|
| LLM03 Supply Chain | ✅ | T1–T7, plus the admission gate (T8) |
| LLM04 Data & Model Poisoning | ✅ | revision pinning, provenance verification, safetensors, admission gate |
| LLM01 Prompt Injection | 🚧 | input guardrails + red-team gate (Pillars 3–4) |
| LLM02 Sensitive Info Disclosure | 🚧 | output scanning, audit log (Pillars 3, 5) |
| LLM05 Improper Output Handling | 🚧 | output guardrails, schema enforcement (Pillar 3) |
| LLM06 Excessive Agency | 🚧 | scoped RBAC, least privilege (Pillar 3) |
| LLM07 System Prompt Leakage | 🚧 | prompt isolation, red-team probes (Pillars 3–4) |
| LLM08 Vector/Embedding Weaknesses | 🚧 | RAG access controls (stretch) |
| LLM09 Misinformation | 🚧 | grounding, promptfoo assertions (Pillar 4) |
| LLM10 Unbounded Consumption | 🚧 | token quotas, cost alerts (Pillars 3, 5) |

## MITRE ATLAS

| Technique | Status | Control |
|---|---|---|
| AML.T0010 ML Supply Chain Compromise | ✅ | scan + sign + verify chain + admission gate |
| AML.T0018 Backdoor ML Model | ✅ partial | provenance pinning detects substitution; a backdoor trained into the *original* weights is not detectable here |
| AML.T0019 Publish Poisoned Datasets | ❌ | upstream of this platform |
| AML.T0051 LLM Prompt Injection | 🚧 | Pillars 3–4 |
| AML.T0057 LLM Data Leakage | 🚧 | Pillars 3, 5 |

## Known limitations

Stated plainly, because a threat model that only lists wins is marketing:

- **A backdoor baked into the upstream weights is not detected.** The pipeline
  proves *provenance and integrity* — that these are the exact bytes published at
  that revision — not *benignity*. Weight-level backdoor detection is an open
  research problem.
- **`key` mode trusts a local key file.** See T7.
- **Kyverno does not verify the model signature itself.** It enforces the pod
  shape; the init container does the cryptography. See T8.
- **No runtime controls exist yet.** Pillars 3–5 are scaffolding, not mitigations.
