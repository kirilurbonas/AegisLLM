#!/usr/bin/env bash
# Initialise and configure Vault for AegisLLM. Idempotent — safe to re-run.
#
# What this sets up, and why each piece exists:
#
#   transit/aegis-cosign   A NON-EXPORTABLE ECDSA key. cosign signs by calling
#                          Vault; the private key never exists on the build host,
#                          so there is nothing on disk to steal. This is what
#                          closes T7 in the threat model for image signing.
#   aegis/ (kv-v2)         The model-signing key and the gateway's system prompt.
#                          model-signing has no KMS backend (elliptic-key,
#                          certificate, PKCS#11 and sigstore signers only), so its
#                          key is stored here and fetched to tmpfs at build time.
#                          Better than a file in the repo; weaker than Transit,
#                          and the threat model says so.
#   kubernetes auth        Workloads authenticate as their ServiceAccount. No
#                          static tokens are handed to pods.
#
# Unseal keys land in keys/vault-init.json (gitignored, 0600). That is acceptable
# for a local cluster and NOT how production works: there, Vault auto-unseals
# against a cloud KMS and no human ever holds the shares.
set -euo pipefail

NS="${VAULT_NAMESPACE:-vault}"
POD="${VAULT_POD:-vault-0}"
INIT_FILE="${VAULT_INIT_FILE:-keys/vault-init.json}"
TRANSIT_KEY="${AEGIS_VAULT_TRANSIT_KEY:-aegis-cosign}"

log() { printf '\033[1;36m%9s\033[0m %s\n' "vault" "$1"; }

vault_exec() { kubectl -n "$NS" exec -i "$POD" -- "$@"; }

# --- wait for the pod ---------------------------------------------------------
log "waiting for $POD to be running"
for _ in $(seq 1 60); do
  phase=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [ "$phase" = "Running" ] && break
  sleep 5
done
[ "${phase:-}" = "Running" ] || { echo "✗ $POD never reached Running"; exit 1; }

# --- initialise ---------------------------------------------------------------
#
# Two rules here, both learned by breaking them:
#
#   1. Detect "already initialised" with a whitespace-tolerant match. `vault
#      status -format=json` emits `"initialized": true` in some versions and
#      `"initialized":true` in others; a literal grep silently decided a healthy
#      Vault was uninitialised.
#   2. NEVER redirect straight into $INIT_FILE. `>` truncates before the command
#      runs, so a failed `operator init` against an already-initialised Vault
#      wiped the unseal keys — permanently sealing a Vault whose shares existed
#      nowhere else. Write to a temp file and move it into place only on success.
vault_status() { vault_exec vault status -format=json 2>/dev/null || true; }

is_initialised() {
  vault_status | grep -Eq '"initialized"[[:space:]]*:[[:space:]]*true'
}

is_unsealed() {
  vault_status | grep -Eq '"sealed"[[:space:]]*:[[:space:]]*false'
}

if is_initialised; then
  log "already initialised"
  if [ ! -s "$INIT_FILE" ]; then
    cat >&2 <<'MSG'
✗ Vault is initialised but the unseal material is missing or empty.

  Its keys exist nowhere else, so this Vault cannot be unsealed again. For a
  local dev cluster the recovery is to destroy its storage and start over:

      kubectl -n vault delete pvc data-vault-0
      kubectl -n vault delete pod vault-0
      make vault

  Anything previously signed with the old Transit key will need re-signing.
MSG
    exit 1
  fi
else
  log "initialising (3 shares, threshold 2)"
  mkdir -p "$(dirname "$INIT_FILE")"
  tmp_init="$(mktemp)"
  if ! vault_exec vault operator init -key-shares=3 -key-threshold=2 -format=json > "$tmp_init"; then
    rm -f "$tmp_init"
    echo "✗ vault operator init failed; $INIT_FILE left untouched" >&2
    exit 1
  fi
  # Only now is it safe to touch the real file.
  mv "$tmp_init" "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  log "unseal material written to $INIT_FILE (gitignored)"
fi

# --- unseal -------------------------------------------------------------------
if is_unsealed; then
  log "already unsealed"
else
  log "unsealing"
  # Read the shares into a variable first, and give each `kubectl exec` its own
  # stdin. Piping jq into `while read` looks natural and does not work here:
  # `kubectl exec -i` inherits the loop's stdin and drains the remaining keys, so
  # exactly one share is ever submitted and Vault stays sealed at threshold 2 --
  # with the script cheerfully reporting success.
  shares=$(jq -r '.unseal_keys_b64[0:2][]' "$INIT_FILE")
  for key in $shares; do
    kubectl -n "$NS" exec "$POD" -- vault operator unseal "$key" >/dev/null </dev/null
  done
  is_unsealed || { echo "✗ Vault is still sealed after submitting shares" >&2; exit 1; }
fi

ROOT_TOKEN=$(jq -r .root_token "$INIT_FILE")

# --- engines, policies, roles -------------------------------------------------
log "configuring engines, policies and Kubernetes auth"
vault_exec sh -s <<EOF >/dev/null
set -e
export VAULT_TOKEN='$ROOT_TOKEN'

vault secrets enable transit 2>/dev/null || true
# exportable and allow_plaintext_backup are left at their defaults (false).
# That is the security property: not even an operator with the root token can
# read this private key out of Vault.
vault write -f transit/keys/$TRANSIT_KEY type=ecdsa-p256 2>/dev/null || true

vault secrets enable -version=2 -path=aegis kv 2>/dev/null || true
vault auth enable kubernetes 2>/dev/null || true
vault write auth/kubernetes/config \
  kubernetes_host="https://\$KUBERNETES_PORT_443_TCP_ADDR:443" >/dev/null

cat > /tmp/aegis-signer.hcl <<'POLICY'
path "transit/sign/$TRANSIT_KEY"   { capabilities = ["update"] }
path "transit/verify/$TRANSIT_KEY" { capabilities = ["update"] }
path "transit/keys/$TRANSIT_KEY"   { capabilities = ["read"] }
path "aegis/data/signing/*"        { capabilities = ["read", "create", "update"] }
POLICY
vault policy write aegis-signer /tmp/aegis-signer.hcl

cat > /tmp/aegis-gateway.hcl <<'POLICY'
path "aegis/data/gateway/*" { capabilities = ["read"] }
POLICY
vault policy write aegis-gateway /tmp/aegis-gateway.hcl

vault write auth/kubernetes/role/aegis-gateway \
  bound_service_account_names=aegis-gateway \
  bound_service_account_namespaces=aegis \
  policies=aegis-gateway ttl=1h
EOF

# --- model-signing key --------------------------------------------------------
# Generated by `aegis keys rotate --init`, not here: the Vault image has no
# openssl and no egress to install it, and piping a generated key through the
# shell would put it in the host's process table. The CLI generates it in memory
# with the `cryptography` library already in this project's dependency tree and
# PUTs it straight to Vault.

log "ready. Export credentials with:  eval \$(make vault-env)"
