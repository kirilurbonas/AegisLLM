# Threat model

Scope of this document: the model supply chain (Pillar 1), the platform
foundation (Pillar 0), the CI/CD and admission gate (Pillar 2), the runtime
gateway (Pillar 3), and the identity and secrets layer — the parts that exist. Runtime threats are listed
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

### T7 — Signing key compromise (**mitigated for cosign; partially for model-signing**)
The keys are the crown jewels: whoever holds them can forge provenance for any
model and every downstream check will pass.

*Controls:*
- **cosign / OCI manifest signing — no private key exists on the build host.**
  The key is a Vault **Transit** key created non-exportable, so signing is an API
  call. `exportable: false` is not a policy that can be relaxed after the fact:
  Vault will not emit the private half to anyone, including an operator holding
  the root token. Verified: `vault read transit/keys/aegis-cosign` reports
  `exportable: false`, and the whole supply chain signs and verifies with the
  local key files deleted.
- **model-signing — key held in Vault kv-v2.** `model_signing` offers only
  elliptic-key, certificate, PKCS#11 and sigstore signers, so there is no KMS
  backend to use. The key is generated in process memory by `aegis keys rotate`,
  PUT straight to Vault, and fetched to a 0600 file under tmpfs only for the
  moments a signature is produced, then deleted in a `finally` block.
- Rotation is a single command (`make keys-rotate`).

*Residual risk:* the model-signing key is necessarily materialised to sign, so a
host compromise during a signing run could capture it. It is a smaller window
than a key committed beside the code, and it is **not** equivalent to Transit —
the two are deliberately not described as the same control. CI uses the sigstore
keyless path, where no long-lived key exists at all. Closing this properly needs
either PKCS#11 (an HSM) or KMS support upstream in `model_signing`.

*Also residual:* Vault's unseal shares live in a gitignored file on the developer
machine. Production auto-unseals against a cloud KMS and no human holds a share.

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

### T14 — Unauthenticated access to the model (**mitigated**)
Until this was fixed the gateway had **no authentication at all**. It read an
`x-aegis-client` header and believed it, so any caller could pick an identity,
reset their quota by changing a string, and write arbitrary values into the audit
log. This was the single largest gap between "demo" and "production".

*Controls, layered:*
- **Istio `PeerAuthentication: STRICT`** — plaintext connections are refused at
  the proxy. A caller outside the mesh cannot complete a handshake at all
  (verified: `curl` from a non-injected pod fails with connection reset).
- **`RequestAuthentication`** validates a projected Kubernetes ServiceAccount
  token — signature, issuer, expiry, and **audience**, so a token minted for a
  different service cannot be replayed here. The JWKS is inlined at apply time
  rather than exposing cluster OIDC discovery to anonymous callers.
- **`AuthorizationPolicy`** denies the namespace by default and allows only
  requests carrying a validated principal. Health probes are exempted by path.
- **The application fails closed too.** `gateway/auth.py` reads only
  `x-aegis-principal`, which the proxy overwrites on every request, and refuses
  service when it is absent. The dev escape hatch is itself refused when
  `KUBERNETES_SERVICE_HOST` is set, so a misconfigured deployment cannot silently
  serve unauthenticated traffic.
- Quotas key on the verified subject, so they can no longer be reset by a header.

*Evidence:* `make demo-auth` — no credentials, a forged `x-aegis-principal`, the
old `x-aegis-client`, and a garbage bearer token are all refused; a real projected
token is served. `tests/test_auth.py` covers the same properties in isolation,
including that a spoofed header cannot change the audited identity.

*Residual risk:* callers are in-cluster workloads. Human/external users would come
from a real IdP as an additional `jwtRules` entry — the shape does not change, but
that path is not built. Authorization is currently coarse (any valid cluster
principal); per-tenant rules are a one-line policy change.

### T9 — Prompt injection (**partially mitigated**)
An attacker crafts input that overrides the system prompt, hijacks the persona, or
injects chat-template role markers.

*Controls:* pattern-based input guardrail (instruction override, persona hijack,
system-prompt extraction, role injection), refusing the request outright — there
is no safe way to sanitise an adversarial prompt. Rejections return categories
only, never the matched pattern, so the guardrail is not an oracle for tuning an
attack.

*Residual risk — stated plainly, because this is the control most often
oversold:* **pattern matching does not stop a determined adversary.** Paraphrase,
encoding, translation, and multi-turn splitting all defeat it. The regexes catch
known shapes and casual attempts. What actually bounds the damage is T11 below.

*Evidence:* `make demo-guardrails` against the deployed gateway; the must-not-fire
tests in `tests/test_guardrails.py` guard against the false positives that get a
guardrail switched off.

### T10 — Sensitive data disclosure (**mitigated**)
Secrets or personal data flow into the model, into logs, or back out in a response.

*Controls:* secrets in a prompt are blocked (never reaching model or log); PII is
redacted before the model sees it, so the request still works; output PII is
redacted and output secrets block the response entirely with no partial content
returned. The audit log records categories and counts, never prompt text — an
audit trail full of PII is its own breach.

*Evidence:* `test_the_model_never_sees_a_blocked_prompt`,
`test_audit_summary_excludes_the_prompt_text`, `test_output_secrets_are_blocked_entirely`.

### T11 — Excessive agency after a successful injection (**mitigated**)
The assumption here is that T9 *will* eventually be bypassed. What can the model
do then?

*Controls, all architectural:* the gateway pod has no egress to the internet
(NetworkPolicy, verified enforced on this cluster — a public-internet connect from
inside the pod times out while the internal registry resolves); it has no tools,
no credentials, and no registry client; `TRANSFORMERS_OFFLINE=1` with no oras or
cosign in the image means it cannot fetch a model even if fully compromised; the
model volume is mounted read-only so the component exposed to untrusted input
cannot rewrite its own weights.

*Residual risk:* NetworkPolicy is pod-scoped and init containers share the
network namespace, so the registry must stay reachable for the pod's lifetime.
Kubernetes cannot express "only the init container may egress"; an Istio
authorization policy is the next step.

### T12 — Unbounded consumption (**mitigated**)
*Controls:* per-client request and token quotas in a sliding window, a hard input
length cap, and a generation cap enforced in the backend regardless of what the
caller requests. *Evidence:* verified live — request 61 of 60 returns 429.
*Now cluster-wide.* The sliding window lives in Redis and the whole
check-and-record runs as one Lua script, so it is atomic: split across separate
reads and writes, two replicas could each observe the same count and each decide
there was room. Verified on two replicas with a limit of 60/min — 70 requests
produce exactly 60 × 200 and 10 × 429. Before this, the same test returned 70 ×
200, which is the `replicas x limit` bug in one line.

*Residual risk, and it is a deliberate trade:* if Redis is unreachable the limiter
degrades to per-process counting rather than refusing traffic. During an outage
the effective limit rises to `replicas x limit`. Failing closed would turn a Redis
blip into a full outage of the model service, which is the wrong trade for a
control whose job is bounding cost and abuse rather than acting as a safety
interlock. The degradation is logged once (not per request) and is an operational
signal — it is how two real misconfigurations in this cluster were caught.

### T15 — Workload escape and noisy neighbours (**mitigated**)
A compromised or simply badly-behaved pod in the namespace escalating privileges,
or starving its neighbours.

*Controls:* Pod Security Admission `restricted` is enforced on the `aegis`
namespace — non-root, no privilege escalation, all capabilities dropped, seccomp
required, on every container including injected sidecars. A `ResourceQuota` caps
the namespace and a `LimitRange` gives every container a memory limit whether or
not its author wrote one. An ingress `NetworkPolicy` means only mesh callers and
kubelet probes can open a connection to the gateway at all, so the identity layer
is not the single thing standing between an arbitrary pod and the model.

*Evidence:* enforcement is real, not declarative — `restricted` rejected the
project's own test-client manifest until it declared `runAsNonRoot` and a seccomp
profile, and rejected every Istio-injected pod until the CNI plugin removed the
privileged `istio-init` container.

*Residual risk:* PSA is namespace-scoped. Cluster-wide enforcement, and policy for
the namespaces Istio and Vault run in, is not addressed here.

### T13 — System prompt leakage (**partially mitigated**)
*Controls:* the system prompt is supplied from a Kubernetes Secret, not baked into
the image or manifest; the output guardrail carries a canary fragment and blocks
any response reproducing it verbatim.
*Residual risk:* a paraphrased system prompt is not detected. Canary matching
catches verbatim leakage only.

## OWASP LLM Top 10 (2025) coverage

| Risk | Status | Control |
|---|---|---|
| LLM03 Supply Chain | ✅ | T1–T7, plus the admission gate (T8) |
| LLM04 Data & Model Poisoning | ✅ | revision pinning, provenance verification, safetensors, admission gate |
| LLM01 Prompt Injection | ⚠️ partial | input guardrail (weak); egress lockdown bounds impact (T9, T11) |
| LLM02 Sensitive Info Disclosure | ✅ | secret/PII detection both directions, PII-free audit log (T10) |
| LLM05 Improper Output Handling | ✅ | typed response schema, output guardrail, no partial content on block |
| LLM06 Excessive Agency | ✅ | no egress, no tools, no credentials, read-only weights (T11) |
| LLM07 System Prompt Leakage | ⚠️ partial | Secret-supplied prompt + canary detection; verbatim only (T13) |
| LLM08 Vector/Embedding Weaknesses | 🚧 | RAG access controls (stretch) |
| LLM09 Misinformation | 🚧 | grounding, promptfoo assertions (Pillar 4) |
| LLM10 Unbounded Consumption | ✅ | request + token quotas, input and generation caps (T12) |

## MITRE ATLAS

| Technique | Status | Control |
|---|---|---|
| AML.T0010 ML Supply Chain Compromise | ✅ | scan + sign + verify chain + admission gate |
| AML.T0018 Backdoor ML Model | ✅ partial | provenance pinning detects substitution; a backdoor trained into the *original* weights is not detectable here |
| AML.T0019 Publish Poisoned Datasets | ❌ | upstream of this platform |
| AML.T0051 LLM Prompt Injection | ⚠️ partial | pattern guardrail + architectural containment |
| AML.T0057 LLM Data Leakage | ✅ | output guardrails + egress lockdown |

## Known limitations

Stated plainly, because a threat model that only lists wins is marketing:

- **A backdoor baked into the upstream weights is not detected.** The pipeline
  proves *provenance and integrity* — that these are the exact bytes published at
  that revision — not *benignity*. Weight-level backdoor detection is an open
  research problem.
- **`key` mode trusts a local key file.** See T7.
- **Kyverno does not verify the model signature itself.** It enforces the pod
  shape; the init container does the cryptography. See T8.
- **Prompt-injection detection is pattern-based and will be bypassed.** It is a
  filter, not a defence. The architectural containment in T11 is what bounds the
  blast radius, and it is the part worth trusting.
- **The demo model is `sshleifer/tiny-gpt2`.** It is an untrained stub that emits
  gibberish. That is deliberate — the security scaffolding is the product, and
  the guardrails act on text regardless of whether it is coherent. No claim is
  made about output quality.
- **No red-teaming yet.** Pillars 4-5 are scaffolding, not mitigations.
