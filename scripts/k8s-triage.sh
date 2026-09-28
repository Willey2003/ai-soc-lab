#!/usr/bin/env bash
# Deploy the AI triage service without touching anything that already runs in
# the cluster.
#
#   ./scripts/k8s-triage.sh preflight   # check permissions/storage, show the plan, change nothing
#   ./scripts/k8s-triage.sh up          # deploy / update
#   ./scripts/k8s-triage.sh status
#   ./scripts/k8s-triage.sh demo        # push the sample alerts through it
#   ./scripts/k8s-triage.sh open        # port-forward the queue to localhost:8020
#   ./scripts/k8s-triage.sh down        # remove only what this script created
#
# Env:
#   NAMESPACE      target namespace (default soc-triage). If it exists and wasn't
#                  created for this lab (e.g. "playground"), the lab shares it:
#                  no quota, no namespace-wide network policy, only objects
#                  labelled app.kubernetes.io/part-of=soc-triage are created.
#   STORAGE        pvc | ephemeral. Default: pvc if the cluster has a default
#                  StorageClass (or STORAGE_CLASS is set), otherwise ephemeral
#                  (emptyDir: model and triage history are lost on pod restart).
#   STORAGE_CLASS  StorageClass for the two PVCs.
#   IMAGE_TAG      image tag (default latest). GHCR_USER + GHCR_TOKEN for a private image.
#   KUBECTL, KUBE_CONTEXT
set -euo pipefail

NS="${NAMESPACE:-soc-triage}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ROOT}/k8s/triage"
SECRETS="${DIR}/secrets.env"
KUBECTL="${KUBECTL:-kubectl}"
[[ -n "${KUBE_CONTEXT:-}" ]] && KUBECTL="${KUBECTL} --context ${KUBE_CONTEXT}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
PART_OF="app.kubernetes.io/part-of=soc-triage"

# Decided by plan(); guard() only needs NS.
MODE=""            # create | dedicated | shared
WITH_GUARDRAILS=0  # ResourceQuota + LimitRange
STORAGE_MODE=""

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==> WARNING:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
can() { ${KUBECTL} auth can-i "$@" >/dev/null 2>&1; }

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
}

setting() { grep -E "^$1=" "${DIR}/triage.env" | tail -1 | cut -d= -f2- || true; }

# With ALERT_SOURCE=indexer, make sure the indexer actually exists before deploying.
check_alert_source() {
    local source url host svc ns
    source="$(setting ALERT_SOURCE)"
    log "Alert source: ${source:-simulate}"
    [[ "${source}" == "indexer" ]] || return 0
    grep -qE '^INDEXER_PASSWORD=.+' "${SECRETS}" \
        || die "ALERT_SOURCE=indexer but INDEXER_PASSWORD is empty in ${SECRETS}"
    url="$(setting INDEXER_URL)"
    host="${url#*://}"; host="${host%%[:/]*}"
    if [[ "${host}" == *.svc || "${host}" == *.svc.cluster.local ]]; then
        svc="${host%%.*}"; ns="${host#*.}"; ns="${ns%%.*}"
        ${KUBECTL} -n "${ns}" get service "${svc}" >/dev/null 2>&1 || die "no Wazuh indexer at ${url}:
    service ${svc} not found in namespace ${ns}.
    Fix INDEXER_URL in k8s/triage/triage.env, or set ALERT_SOURCE=simulate to run without Wazuh."
        log "Found Wazuh indexer service ${ns}/${svc}"
    else
        log "Indexer is outside the cluster (${host}); make sure pods can reach it"
    fi
}

# Work out how to deploy into NS given what exists and what we're allowed to do.
plan() {
    if ${KUBECTL} get namespace "${NS}" >/dev/null 2>&1; then
        local owner
        owner="$(${KUBECTL} get namespace "${NS}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}' 2>/dev/null || true)"
        if [[ "${owner}" == "soc-triage" ]]; then MODE=dedicated; else MODE=shared; fi
    elif [[ -n "${NAMESPACE:-}" && "${NAMESPACE}" != "soc-triage" ]]; then
        die "namespace ${NS} does not exist (and this script only creates soc-triage)"
    elif can create namespaces; then
        MODE=create
    else
        local me subject
        me="$(${KUBECTL} auth whoami -o jsonpath='{.status.userInfo.username}' 2>/dev/null || true)"
        if [[ "${me}" == system:serviceaccount:* ]]; then
            subject="--serviceaccount=$(echo "${me}" | cut -d: -f3):$(echo "${me}" | cut -d: -f4)"
        else
            subject="--user=${me:-<your-user>}"
        fi
        die "your account (${me:-unknown}) can't create namespaces, and ${NS} doesn't exist yet. Either:
    a) deploy into an existing namespace you can write to, e.g.:
         NAMESPACE=playground $0 preflight
    b) ask a cluster admin to run this once from the repo root, then re-run $0 preflight:
         kubectl apply -f k8s/triage/namespace.yaml
         kubectl label namespace soc-triage ${PART_OF}
         kubectl apply -n soc-triage -f k8s/triage/guardrails.yaml
         kubectl create rolebinding soc-triage-deployer -n soc-triage --clusterrole=admin ${subject}"
    fi

    case "${MODE}" in
        create) log "Will create namespace ${NS} (dedicated to this lab)" ;;
        dedicated) log "Using namespace ${NS} (already dedicated to this lab)" ;;
        shared) log "Sharing existing namespace ${NS}: no quota and no namespace-wide network policy will be added; only objects labelled ${PART_OF} are created" ;;
    esac

    WITH_GUARDRAILS=0
    if [[ "${MODE}" != "shared" ]]; then
        if [[ "${MODE}" == "create" ]] || can create resourcequotas -n "${NS}"; then
            WITH_GUARDRAILS=1
        elif ${KUBECTL} -n "${NS}" get resourcequota soc-triage-quota >/dev/null 2>&1; then
            log "Quota soc-triage-quota already set by an admin; leaving it alone"
        else
            warn "can't create the ResourceQuota in ${NS}; deploying without it (ask an admin to apply k8s/triage/guardrails.yaml)"
        fi
    fi

    # Storage
    if [[ -n "${STORAGE:-}" ]]; then
        STORAGE_MODE="${STORAGE}"
    elif [[ -n "${STORAGE_CLASS:-}" ]]; then
        STORAGE_MODE=pvc
    elif ${KUBECTL} get storageclass -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -q .; then
        STORAGE_MODE=pvc
    else
        STORAGE_MODE=ephemeral
    fi
    case "${STORAGE_MODE}" in
        pvc) log "Storage: PersistentVolumeClaims${STORAGE_CLASS:+ (class ${STORAGE_CLASS})}" ;;
        ephemeral) log "Storage: ephemeral emptyDir (no default StorageClass). The model is re-downloaded and triage history is lost when a pod restarts. Set STORAGE_CLASS=<name> to keep them." ;;
        *) die "STORAGE must be pvc or ephemeral" ;;
    esac
}

check_permissions() {
    local missing=() r
    for r in deployments.apps services persistentvolumeclaims configmaps secrets \
             networkpolicies.networking.k8s.io serviceaccounts; do
        [[ "${STORAGE_MODE}" == "ephemeral" && "${r}" == persistentvolumeclaims ]] && continue
        can create "${r}" -n "${NS}" || missing+=("${r}")
    done
    [[ "${MODE}" == "create" ]] && return 0  # we'll own the namespace; checked via 'create namespaces'
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "your account can't create these in namespace ${NS}: ${missing[*]}
    Pick a namespace you can write to (NAMESPACE=...), or ask an admin for a RoleBinding to the 'admin' ClusterRole there."
    fi
    log "Permissions in ${NS}: OK"
}

# In a shared namespace, refuse to overwrite anything we didn't create.
check_collisions() {
    [[ "${MODE}" == "shared" ]] || return 0
    local obj owner clash=()
    for obj in deployment/ollama deployment/soc-triage service/ollama service/soc-triage \
               serviceaccount/soc-triage persistentvolumeclaim/ollama-models persistentvolumeclaim/triage-data \
               networkpolicy/ollama-from-triage networkpolicy/triage-from-namespace; do
        if ${KUBECTL} -n "${NS}" get "${obj}" >/dev/null 2>&1; then
            owner="$(${KUBECTL} -n "${NS}" get "${obj}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}')"
            [[ "${owner}" == "soc-triage" ]] || clash+=("${obj}")
        fi
    done
    [[ ${#clash[@]} -eq 0 ]] || die "namespace ${NS} already has objects with the lab's names that it didn't create: ${clash[*]}"
}

render() {
    # Build a throwaway kustomization around the committed files, so the chosen
    # namespace, image tag and storage never require editing the repo.
    local tmp rc=0 res
    tmp="$(mktemp -d)"
    cp -R "${DIR}/." "${tmp}/"
    res="  - networkpolicy.yaml
  - ollama.yaml
  - triage.yaml"
    [[ "${MODE}" == "create" || "${MODE}" == "" ]] && res="  - namespace.yaml
${res}"
    [[ "${MODE}" != "shared" ]] && res="${res}
  - netpol-default-deny.yaml"
    [[ ${WITH_GUARDRAILS} -eq 1 ]] && res="${res}
  - guardrails.yaml"
    {
        cat <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${NS}
resources:
${res}
labels:
  - pairs:
      app.kubernetes.io/part-of: soc-triage
      app.kubernetes.io/managed-by: kustomize
    includeSelectors: false
configMapGenerator:
  - name: soc-triage-config
    envs: [triage.env]
secretGenerator:
  - name: soc-triage-secrets
    envs: [secrets.env]
images:
  - name: ghcr.io/willey2003/soc-triage
    newTag: ${IMAGE_TAG}
patches:
EOF
        if [[ "${STORAGE_MODE}" == "ephemeral" ]]; then
            cat <<'EOF'
  - patch: |-
      $patch: delete
      apiVersion: v1
      kind: PersistentVolumeClaim
      metadata:
        name: ollama-models
  - patch: |-
      $patch: delete
      apiVersion: v1
      kind: PersistentVolumeClaim
      metadata:
        name: triage-data
  - target: {kind: Deployment, name: ollama}
    patch: |-
      - op: replace
        path: /spec/template/spec/volumes/0
        value: {name: models, emptyDir: {sizeLimit: 20Gi}}
  - target: {kind: Deployment, name: soc-triage}
    patch: |-
      - op: replace
        path: /spec/template/spec/volumes/0
        value: {name: data, emptyDir: {sizeLimit: 1Gi}}
EOF
        elif [[ -n "${STORAGE_CLASS:-}" ]]; then
            local pvc
            for pvc in ollama-models triage-data; do
                cat <<EOF
  - target: {kind: PersistentVolumeClaim, name: ${pvc}}
    patch: |-
      - op: add
        path: /spec/storageClassName
        value: ${STORAGE_CLASS}
EOF
            done
        fi
        [[ -f "${tmp}/secrets.env" ]] || : > "${tmp}/secrets.env"
    } > "${tmp}/kustomization.yaml"
    # an empty "patches:" is invalid
    grep -q '^  - ' <(sed -n '/^patches:/,$p' "${tmp}/kustomization.yaml") \
        || sed -i.bak '/^patches:$/d' "${tmp}/kustomization.yaml"
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

prepare() {
    ensure_secrets
    log "Cluster context: $(${KUBECTL} config current-context 2>/dev/null || echo '?')"
    ${KUBECTL} version >/dev/null 2>&1 || die "cannot reach the cluster with '${KUBECTL}'"
    plan
    check_permissions
    check_collisions
    check_alert_source
    MANIFEST="$(mktemp)"
    render > "${MANIFEST}"
    guard "${MANIFEST}"
}

cmd_preflight() {
    prepare
    log "Everything below goes into namespace ${NS} only:"
    grep -E '^kind: ' "${MANIFEST}" | sort | uniq -c
    if [[ "${MODE}" == "create" ]]; then
        log "Server-side dry run of the namespace; the rest is validated client-side until it exists:"
        ${KUBECTL} apply --dry-run=server -f "${DIR}/namespace.yaml" | sed 's/^/    /'
        ${KUBECTL} apply --dry-run=client -f "${MANIFEST}" | sed 's/^/    /'
    else
        log "Server-side dry run (the API server validates every object, nothing is saved):"
        ${KUBECTL} apply --dry-run=server -f "${MANIFEST}" | sed 's/^/    /'
    fi
    rm -f "${MANIFEST}"
    log "Preflight OK. Deploy with the same settings: ${NAMESPACE:+NAMESPACE=${NAMESPACE} }${STORAGE:+STORAGE=${STORAGE} }${STORAGE_CLASS:+STORAGE_CLASS=${STORAGE_CLASS} }$0 up"
}

cmd_up() {
    prepare
    if [[ "${MODE}" == "create" ]]; then
        ${KUBECTL} apply -f "${DIR}/namespace.yaml"
        ${KUBECTL} label namespace "${NS}" "${PART_OF}" --overwrite >/dev/null
    fi
    if [[ -n "${GHCR_TOKEN:-}" ]]; then
        ${KUBECTL} -n "${NS}" create secret docker-registry ghcr-pull \
            --docker-server=ghcr.io --docker-username="${GHCR_USER:-$(whoami)}" \
            --docker-password="${GHCR_TOKEN}" --dry-run=client -o yaml \
            | ${KUBECTL} label --local -f - "${PART_OF}" -o yaml \
            | ${KUBECTL} apply -f -
    fi
    ${KUBECTL} apply -f "${MANIFEST}"
    rm -f "${MANIFEST}"
    log "Waiting for Ollama..."
    ${KUBECTL} -n "${NS}" rollout status deploy/ollama --timeout=10m
    log "Waiting for the triage service (first start downloads the model, a few minutes)..."
    ${KUBECTL} -n "${NS}" rollout status deploy/soc-triage --timeout=30m
    cmd_status
}

cmd_status() {
    ${KUBECTL} -n "${NS}" get deploy,pods,svc -l "${PART_OF}" 2>/dev/null || true
    ${KUBECTL} -n "${NS}" get pods -l 'app.kubernetes.io/name in (ollama,soc-triage)'
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
    log "Open the queue with: ${NAMESPACE:+NAMESPACE=${NAMESPACE} }$0 open"
}

cmd_open() {
    log "Queue: http://localhost:8020/?key=$(api_key)"
    ${KUBECTL} -n "${NS}" port-forward svc/soc-triage 8020:8020
}

cmd_down() {
    ${KUBECTL} get namespace "${NS}" >/dev/null 2>&1 || { log "Nothing to remove"; return; }
    local owner
    owner="$(${KUBECTL} get namespace "${NS}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}')"
    if [[ "${owner}" == "soc-triage" && "${NS}" == "soc-triage" ]] && can delete namespaces; then
        read -r -p "Delete namespace ${NS} and its data (models, triage history)? [y/N] " yes
        [[ "${yes}" == "y" || "${yes}" == "Y" ]] || { log "Aborted"; return; }
        ${KUBECTL} delete namespace "${NS}"
        return
    fi
    log "These lab objects in ${NS} will be deleted (nothing else):"
    ${KUBECTL} -n "${NS}" get deploy,svc,pvc,cm,secret,netpol,sa,resourcequota,limitrange -l "${PART_OF}" -o name
    read -r -p "Delete them? [y/N] " yes
    [[ "${yes}" == "y" || "${yes}" == "Y" ]] || { log "Aborted"; return; }
    ${KUBECTL} -n "${NS}" delete deploy,svc,pvc,cm,secret,netpol,sa,resourcequota,limitrange -l "${PART_OF}"
}

case "${1:-}" in
    preflight) cmd_preflight ;;
    up) cmd_up ;;
    status) cmd_status ;;
    demo) cmd_demo ;;
    open) cmd_open ;;
    down) cmd_down ;;
    render) prepare; cat "${MANIFEST}"; rm -f "${MANIFEST}" ;;
    *) sed -n '2,24p' "$0"; exit 1 ;;
esac
