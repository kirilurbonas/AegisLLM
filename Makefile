SHELL := /bin/bash
.DEFAULT_GOAL := help

TF      := terraform -chdir=infra/terraform/kind
CLUSTER := aegis

REQUIRED_BINS := uv kind kubectl helm terraform oras cosign openssl

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
	brew install kind kubectl helm terraform oras cosign

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
