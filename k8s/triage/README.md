# AI triage on Kubernetes (isolated)

Deploys the [triage service](../../triage/README.md) and its own Ollama into a
dedicated `soc-triage` namespace. Nothing in your existing setup is created,
changed or deleted:

- **One namespace only.** `scripts/k8s-triage.sh` renders the manifests and
  refuses to apply if any object is outside `soc-triage` (no cluster-wide
  RBAC, CRDs or objects in `soc-lab`). It also refuses to touch a `soc-triage`
  namespace it didn't create.
- **Read-only link to Wazuh.** Alerts are pulled from the Wazuh indexer over
  HTTPS with a read-only user (the lab's `grafana_reader`), so the Wazuh
  manager's volumes and config stay as they are.
- **Can't starve other workloads.** A ResourceQuota caps the namespace at
  3 CPU / 8 GiB requested and 6 CPU / 12 GiB limit, 40 GiB of storage, and no
  NodePorts or LoadBalancers. Both Deployments use `Recreate` so a rollout never
  needs double resources.
- **Closed to the rest of the cluster.** NetworkPolicies deny all ingress from
  other namespaces; only the triage pod can call Ollama. Access is through
  `kubectl port-forward`.
- **Hardened pods.** The triage pod meets the `restricted` Pod Security level
  (non-root, read-only root filesystem, no capabilities, no service account
  token). Ollama's image needs root, so the namespace enforces `baseline`.

```
 soc-lab (existing, untouched)             soc-triage (new)
 ┌───────────────────────┐   HTTPS, read   ┌──────────────────────────┐    ┌──────────┐
 │ wazuh-indexer :9200    │◀───────────────│ soc-triage :8020          │───▶│ ollama    │
 └───────────────────────┘   only          │ SQLite PVC 1Gi            │    │ PVC 20Gi  │
                                           └──────────────────────────┘    └──────────┘
                                                      │ optional, redacted
                                                      ▼
                                                Groq (free tier)
```

## Deploy

Needs `kubectl` pointed at the lab cluster, a default StorageClass, and about
4 GiB of free memory for Ollama.

```bash
# 1. Secrets (git-ignored). TRIAGE_API_KEY is generated for you.
cp k8s/triage/secrets.env.example k8s/triage/secrets.env
$EDITOR k8s/triage/secrets.env          # INDEXER_PASSWORD (+ HOSTED_API_KEY if using Groq)

# 2. See exactly what will be created; changes nothing
./scripts/k8s-triage.sh preflight

# 3. Deploy (first start downloads the model, a few minutes)
./scripts/k8s-triage.sh up

# 4. Try it
./scripts/k8s-triage.sh demo            # replays 6 sample Wazuh alerts
./scripts/k8s-triage.sh open            # http://localhost:8020/?key=...
```

Settings live in `k8s/triage/triage.env`: the indexer URL (defaults to
`wazuh-indexer.soc-lab.svc.cluster.local:9200`, change it if your Wazuh runs
elsewhere, e.g. in Docker on another host), AI backends, model, minimum rule
level. Edit and re-run `up`; the ConfigMap name changes with its content so the
pod restarts with the new values.

### Container image

The image is built by `.github/workflows/triage-image.yml` and published to
`ghcr.io/willey2003/soc-triage`: `latest` from `main`, plus a tag per branch
and per commit (`sha-…`). Pick one with `IMAGE_TAG=... ./scripts/k8s-triage.sh up`.

The repo is private, so the package is too. Either make the package public in
GitHub (Packages, soc-triage, Package settings) or give the cluster a token
with `read:packages`:

```bash
GHCR_USER=Willey2003 GHCR_TOKEN=ghp_xxx ./scripts/k8s-triage.sh up
```

That creates an image pull secret inside `soc-triage` only.

### Switching to the free hosted AI

In `triage.env` set `LLM_PROVIDERS=hosted,heuristic` (or
`ollama,hosted,heuristic` for local-first), put `HOSTED_API_KEY` in
`secrets.env`, and re-run `up`. If you drop Ollama entirely you can also
remove `ollama.yaml` from `kustomization.yaml` to save the 4 GiB.

### Verifying the indexer TLS certificate

`INDEXER_VERIFY_TLS=false` by default because the lab's indexer uses its own
CA. To verify it, create a secret with that CA in `soc-triage`, mount it in
the triage pod, and set `INDEXER_CA_FILE` to the mounted path.

## Remove

```bash
./scripts/k8s-triage.sh down    # asks first; deletes only the soc-triage namespace
```
