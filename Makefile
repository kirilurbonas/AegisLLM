SHELL := /bin/bash
.DEFAULT_GOAL := help

TF      := terraform -chdir=infra/terraform/kind
CLUSTER := aegis

REQUIRED_BINS := uv kind kubectl helm terraform oras cosign openssl

# Registry names. `localhost:5001` is the host-side view; in-cluster workloads
# must use the service name, because inside a pod "localhost" is the pod itself.
REGISTRY_HOST := localhost:5001
REGISTRY_IN   := aegis-registry:5000
VERIFIER_IMAGE := $(REGISTRY_HOST)/aegis-verifier:dev

# Kyverno reads container-image signatures from the legacy `sha256-<digest>.sig`
# tag. cosign v3 stopped writing that tag -- it publishes a sigstore bundle as an
# OCI 1.1 referrer instead, which Kyverno 1.18 does not recognise, and the
# resulting error ("no signatures found") is indistinguishable from an unsigned
# image. So container images are signed with a pinned cosign v2 binary until
# Kyverno supports the new format. Model artifacts still use the system cosign.
COSIGN2       := bin/cosign2
COSIGN2_VERSION := 2.4.3
COSIGN2_OS    := $(shell uname -s | tr '[:upper:]' '[:lower:]')
COSIGN2_ARCH  := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

MODEL_DIGEST = $(shell jq -r .digest artifacts/reports/*/push.json 2>/dev/null | head -1)
MODEL_REF    = $(REGISTRY_IN)/models/all-minilm-l6-v2@$(MODEL_DIGEST)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- preflight ---------------------------------------------------------------

.PHONY: check
check: ## Verify the Docker daemon and required binaries are available
	@missing=""; \
	for bin in $(REQUIRED_BINS); do \
		command -v $$bin >/dev/null 2>&1 || missing="$$missing $$bin"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "✗ missing binaries:$$missing"; \
		echo "  run: make tools"; exit 1; \
	fi; \
	echo "✓ all binaries present"
	@docker info >/dev/null 2>&1 || { \
		echo "✗ the Docker daemon is not responding."; \
		echo "  Start Docker Desktop, wait for the whale to settle, then retry."; \
		exit 1; }
	@echo "✓ docker daemon responding"

.PHONY: tools
tools: ## Install missing CLI dependencies via Homebrew
	brew install kind kubectl helm terraform oras cosign kyverno

.PHONY: install
install: ## Sync the Python environment
	uv sync

# --- pillar 1: model supply chain --------------------------------------------

.PHONY: supply-chain
supply-chain: ## Full pipeline: ingest -> scan -> convert -> aibom -> sign -> push -> verify
	uv run aegis all

.PHONY: supply-chain-offline
supply-chain-offline: ## Same, but stop at signing (no registry / Docker required)
	uv run aegis all --skip-registry

.PHONY: demo-tamper
demo-tamper: ## Corrupt a byte of the published model; verification MUST fail
	@uv run aegis tamper
	@echo "--- re-verifying the tampered artifact (expecting rejection) ---"
	@if uv run aegis verify --no-pull; then \
		echo "✗ DEMO FAILED: tampered model verified successfully"; exit 1; \
	else \
		echo "✓ tampered model was rejected, as designed"; \
	fi

.PHONY: test
test: ## Run the test suite (includes the malicious-pickle gate test)
	uv run pytest -q

.PHONY: lint
lint: ## Lint
	uv run ruff check .

.PHONY: test-policies
test-policies: policies/tests/resources.yaml ## Kyverno policy unit tests (offline)
	cd policies/tests && kyverno test .

# Regenerated from examples/ so the tested manifests cannot drift away from the
# ones the README shows and `make demo-admission` applies.
policies/tests/resources.yaml: $(wildcard examples/*.yaml)
	@ref="$(REGISTRY_IN)/models/all-minilm-l6-v2@sha256:$$(printf '1%.0s' {1..64})"; \
	for f in compliant unpinned external no-verifier; do \
		sed "s|AEGIS_MODEL_REF|$$ref|" examples/model-server-$$f.yaml | grep -v '^#'; \
		echo "---"; \
	done > $@
	@echo "→ regenerated $@ from examples/"

# --- pillar 0: cluster + gitops ----------------------------------------------

.PHONY: cluster
cluster: check ## Create the kind cluster, Zot registry, and ArgoCD
	$(TF) init -upgrade
	$(TF) apply -auto-approve
	@$(TF) output

.PHONY: gitops
gitops: ## Apply the app-of-apps so ArgoCD starts reconciling
	@url="$(AEGIS_REPO_URL)"; \
	if [ -z "$$url" ]; then url=$$(git remote get-url origin 2>/dev/null || true); fi; \
	if [ -z "$$url" ]; then \
		echo "✗ no git remote found. ArgoCD reconciles from git, so it needs a"; \
		echo "  reachable repo URL. Push this repo, then re-run — or pass one:"; \
		echo "    make gitops AEGIS_REPO_URL=https://github.com/<you>/aegisllm.git"; \
		exit 1; \
	fi; \
	echo "→ reconciling from $$url"; \
	sed "s|AEGIS_REPO_URL|$$url|" gitops/bootstrap/root-app.yaml | kubectl apply -f -
	@echo "watch with: kubectl -n argocd get applications -w"

.PHONY: argocd-password
argocd-password: ## Print the initial ArgoCD admin password
	@kubectl -n argocd get secret argocd-initial-admin-secret \
		-o jsonpath='{.data.password}' | base64 -d; echo

.PHONY: clean-cluster
clean-cluster: ## Destroy the cluster and registry
	$(TF) destroy -auto-approve

.PHONY: clean
clean: ## Remove local artifacts (keeps signing keys)
	rm -rf artifacts

.PHONY: kubeconfig
kubeconfig: ## Print the export line for this cluster's kubeconfig
	@echo "export KUBECONFIG=$(PWD)/infra/terraform/kind/aegis-config"

# --- pillar 2: admission gate -------------------------------------------------

$(COSIGN2):
	@mkdir -p bin
	@echo "→ fetching cosign v$(COSIGN2_VERSION) (Kyverno-compatible signatures)"
	@curl -fsSL -o $@ "https://github.com/sigstore/cosign/releases/download/v$(COSIGN2_VERSION)/cosign-$(COSIGN2_OS)-$(COSIGN2_ARCH)"
	@chmod +x $@

.PHONY: verifier-image
verifier-image: $(COSIGN2) ## Build, push and sign the verifier init-container image
	docker build --provenance=false --sbom=false \
		--build-arg TARGETARCH=$(COSIGN2_ARCH) -t $(VERIFIER_IMAGE) .
	docker push -q $(VERIFIER_IMAGE)
	@digest=$$(curl -sI -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
		http://$(REGISTRY_HOST)/v2/aegis-verifier/manifests/dev \
		| grep -i docker-content-digest | awk '{print $$2}' | tr -d '\r'); \
	echo "→ signing $(REGISTRY_HOST)/aegis-verifier@$$digest"; \
	COSIGN_PASSWORD="" $(COSIGN2) sign --yes --tlog-upload=false \
		--allow-insecure-registry --key keys/cosign.key \
		"$(REGISTRY_HOST)/aegis-verifier@$$digest"

.PHONY: kyverno
kyverno: ## Install Kyverno and apply the AegisLLM admission policies
	helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
	helm repo update >/dev/null
	helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace \
		--set admissionController.container.extraArgs.allowInsecureRegistry=true \
		--wait --timeout 10m
	kubectl apply -f policies/require-verified-model.yaml
	@uv run python scripts/render_policy.py policies/verify-image-signatures.yaml \
		keys/cosign.pub | kubectl apply -f -
	@kubectl get clusterpolicy

.PHONY: keys-secret
keys-secret: ## Publish the public keys the verifier init container reads
	kubectl create ns aegis --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n aegis create secret generic aegis-public-keys \
		--from-file=cosign.pub=keys/cosign.pub \
		--from-file=aegis-signing.pub=keys/aegis-signing.pub \
		--dry-run=client -o yaml | kubectl apply -f -

.PHONY: demo-admission
demo-admission: ## Prove the gate: a compliant pod runs, three bad ones are refused
	@test -n "$(MODEL_DIGEST)" || { \
		echo "✗ no published model found — run `make supply-chain` first"; exit 1; }
	@echo "── compliant pod (must be ADMITTED and reach Running) ──"
	@kubectl -n aegis delete pod model-server-compliant --ignore-not-found >/dev/null
	@sed "s|AEGIS_MODEL_REF|$(MODEL_REF)|" examples/model-server-compliant.yaml \
		| kubectl apply -f -
	@kubectl -n aegis wait --for=condition=Ready pod/model-server-compliant --timeout=180s
	@echo "→ the serving container sees:"
	@kubectl -n aegis logs model-server-compliant -c server | head -4
	@echo
	@failed=0; \
	for case in unpinned external no-verifier; do \
		echo "── $$case (must be REFUSED) ──"; \
		if sed "s|AEGIS_MODEL_REF|$(MODEL_REF)|" examples/model-server-$$case.yaml \
			| kubectl apply -f - >/tmp/aegis-$$case.out 2>&1; then \
			echo "  ✗ ADMITTED — the gate did not hold"; failed=1; \
		else \
			grep -oE "rule [a-z-]+ failed|(model|verifier)-must-[a-z-]+" \
				/tmp/aegis-$$case.out | head -1 | sed 's/^/  ✓ blocked by rule: /'; \
		fi; \
	done; \
	exit $$failed
