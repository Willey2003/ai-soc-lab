#!/usr/bin/env bash
# Deploy the AI triage service into its own namespace without touching anything
# that already runs in the cluster.
#
#   ./scripts/k8s-triage.sh preflight   # show what would be created, change nothing
#   ./scripts/k8s-triage.sh up          # deploy / update
#   ./scripts/k8s-triage.sh status
#   ./scripts/k8s-triage.sh demo        # push the sample alerts through it
#   ./scripts/k8s-triage.sh open        # port-forward the queue to localhost:8020
#   ./scripts/k8s-triage.sh down        # delete the soc-triage namespace (only if we created it)
#
# Env: IMAGE_TAG (default latest), GHCR_USER + GHCR_TOKEN (private image pull),
#      KUBECTL (default kubectl), KUBE_CONTEXT (default: current context).
set -euo pipefail

NS=soc-triage
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ROOT}/k8s/triage"
SECRETS="${DIR}/secrets.env"
KUBECTL="${KUBECTL:-kubectl}"
[[ -n "${KUBE_CONTEXT:-}" ]] && KUBECTL="${KUBECTL} --context ${KUBE_CONTEXT}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

ensure_secrets() {
    if [[ ! -f "${SECRETS}" ]]; then
        cp "${DIR}/secrets.env.example" "${SECRETS}"
        chmod 600 "${SECRETS}"
        log "Created ${SECRETS} from the example"
    fi
    if ! grep -qE '^TRIAGE_API_KEY=.+' "${SECRETS}"; then
        local key; key="$(openssl rand -hex 32)"
        sed -i.bak "s/^TRIAGE_API_KEY=.*/TRIAGE_API_KEY=${key}/" "${SECRETS}" && rm -f "${SECRETS}.bak"
        log "Generated TRIAGE_API_KEY in ${SECRETS}"
    fi
    grep -qE '^INDEXER_PASSWORD=.+' "${SECRETS}" \
        || log "WARNING: INDEXER_PASSWORD is empty in ${SECRETS}; the service will run but won't see alerts"
}

render() {
    # Render with the chosen image tag without editing the committed kustomization.
    local tmp rc=0; tmp="$(mktemp -d)"
    cp -R "${DIR}/." "${tmp}/"
    sed -i.bak "s/^    newTag: .*/    newTag: ${IMAGE_TAG}/" "${tmp}/kustomization.yaml"
    ${KUBECTL} kustomize "${tmp}" || rc=$?
    rm -rf "${tmp}"
    [[ ${rc} -eq 0 ]] || die "kustomize failed"
}

# Refuse to apply anything that isn't inside our namespace.
guard() {
    local manifest="$1" bad
    bad="$(awk '
        /^---/ { if (kind != "") check(); kind=""; name=""; ns=""; next }
        /^kind: / { kind=$2 }
        /^  name: / && name == "" { name=$2 }
        /^  namespace: / { ns=$2 }
        function check() {
            if (kind == "Namespace") { if (name != "'"${NS}"'") print kind "/" name }
            else if (ns != "'"${NS}"'") print kind "/" name " (namespace: " (ns == "" ? "none" : ns) ")"
        }
        END { if (kind != "") check() }' "${manifest}")"
    [[ -z "${bad}" ]] || die "refusing to apply objects outside namespace ${NS}:"$'\n'"${bad}"
}

check_namespace_owner() {
    if ${KUBECTL} get namespace "${NS}" >/dev/null 2>&1; then
        local owner
        owner="$(${KUBECTL} get namespace "${NS}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}')"
        [[ "${owner}" == "soc-triage" ]] \
            || die "namespace ${NS} already exists and was not created by this lab; not touching it"
    fi
}

cmd_preflight() {
    ensure_secrets
    local ctx; ctx="$(${KUBECTL} config current-context 2>/dev/null || echo '?')"
    log "Cluster context: ${ctx}"
    ${KUBECTL} version >/dev/null 2>&1 || die "cannot reach the cluster with '${KUBECTL}'"
    check_namespace_owner
    local manifest; manifest="$(mktemp)"
    render > "${manifest}"
    guard "${manifest}"
    log "Everything below goes into namespace ${NS} only:"
    grep -E '^kind: ' "${manifest}" | sort | uniq -c
    ${KUBECTL} get storageclass -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
        | grep -q . || log "WARNING: no default StorageClass; the two PVCs will stay Pending until you add one"
    if ${KUBECTL} get namespace soc-lab >/dev/null 2>&1; then
        log "Found existing namespace soc-lab (read over the network only, never modified)"
    fi
    if ${KUBECTL} get namespace "${NS}" >/dev/null 2>&1; then
        log "Server-side dry run (the API server validates every object, nothing is saved):"
        ${KUBECTL} apply --dry-run=server -f "${manifest}" | sed 's/^/    /'
    else
        # Namespaced objects can't be dry-run into a namespace that doesn't exist yet.
        log "Server-side dry run of the namespace; the rest is validated client-side until it exists:"
        ${KUBECTL} apply --dry-run=server -f "${DIR}/namespace.yaml" | sed 's/^/    /'
        ${KUBECTL} apply --dry-run=client -f "${manifest}" | sed 's/^/    /'
    fi
    rm -f "${manifest}"
}

cmd_up() {
    ensure_secrets
    check_namespace_owner
    local manifest; manifest="$(mktemp)"
    render > "${manifest}"
    guard "${manifest}"
    # Namespace first so the pull secret can go in before the pods start.
    ${KUBECTL} apply -f "${DIR}/namespace.yaml"
    ${KUBECTL} label namespace "${NS}" app.kubernetes.io/part-of=soc-triage --overwrite >/dev/null
    if [[ -n "${GHCR_TOKEN:-}" ]]; then
        ${KUBECTL} -n "${NS}" create secret docker-registry ghcr-pull \
            --docker-server=ghcr.io --docker-username="${GHCR_USER:-$(whoami)}" \
            --docker-password="${GHCR_TOKEN}" --dry-run=client -o yaml | ${KUBECTL} apply -f -
    fi
    ${KUBECTL} apply -f "${manifest}"
    rm -f "${manifest}"
    log "Waiting for Ollama..."
    ${KUBECTL} -n "${NS}" rollout status deploy/ollama --timeout=10m
    log "Waiting for the triage service (first start downloads the model, a few minutes)..."
    ${KUBECTL} -n "${NS}" rollout status deploy/soc-triage --timeout=30m
    cmd_status
}

cmd_status() {
    ${KUBECTL} -n "${NS}" get deploy,pods,svc,pvc
    ${KUBECTL} -n "${NS}" exec deploy/soc-triage -c soc-triage -- \
        python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8020/health').read().decode())" \
        2>/dev/null || true
}

api_key() { grep -E '^TRIAGE_API_KEY=' "${SECRETS}" | cut -d= -f2-; }

cmd_demo() {
    log "Replaying samples/wazuh_alerts.jsonl inside the pod..."
    ${KUBECTL} -n "${NS}" exec deploy/soc-triage -c soc-triage -- \
        python -m soc_triage replay samples/wazuh_alerts.jsonl \
        | grep -E '"(priority|verdict|provider|score)"' | paste - - - - || true
    log "Open the queue with: $0 open"
}

cmd_open() {
    log "Queue: http://localhost:8020/?key=$(api_key)"
    ${KUBECTL} -n "${NS}" port-forward svc/soc-triage 8020:8020
}

cmd_down() {
    check_namespace_owner
    ${KUBECTL} get namespace "${NS}" >/dev/null 2>&1 || { log "Nothing to remove"; return; }
    read -r -p "Delete namespace ${NS} and its data (models, triage history)? [y/N] " yes
    [[ "${yes}" == "y" || "${yes}" == "Y" ]] || { log "Aborted"; return; }
    ${KUBECTL} delete namespace "${NS}"
}

case "${1:-}" in
    preflight) cmd_preflight ;;
    up) cmd_up ;;
    status) cmd_status ;;
    demo) cmd_demo ;;
    open) cmd_open ;;
    down) cmd_down ;;
    render) render ;;
    *) sed -n '2,15p' "$0"; exit 1 ;;
esac
