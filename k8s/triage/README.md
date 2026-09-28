# AI triage on Kubernetes (isolated)

Deploys the [triage service](../../triage/README.md) and its own Ollama into a
dedicated `soc-triage` namespace. Nothing in your existing setup is created,
changed or deleted:

- **One namespace only.** `scripts/k8s-triage.sh` renders the manifests and
  refuses to apply if any object is outside the target namespace (no
  cluster-wide RBAC or CRDs). By default that's a new `soc-triage` namespace;
  it can also share an existing one without changing what's already there
  (see [Which namespace](#which-namespace)).
- **No Wazuh required.** By default (`ALERT_SOURCE=simulate`) the service
  replays realistic sample Wazuh alerts (SSH brute force, Mimikatz, reverse
  shell, `/etc/passwd` change...) with fresh timestamps, one a minute, so the AI
  triage runs end to end on any cluster. If you have a Wazuh indexer, switch to
  `ALERT_SOURCE=indexer` and alerts are pulled from it over HTTPS with a
  read-only user; preflight stops you if that indexer isn't there. Real alerts
  can also be pushed in any time with `POST /api/triage`.
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
 Wazuh indexer (optional,                  soc-triage (new)
 any namespace or host)                    ┌──────────────────────────┐    ┌──────────┐
 ┌───────────────────────┐   HTTPS, read   │ soc-triage :8020          │───▶│ ollama    │
 │ wazuh-indexer :9200    │◀ ─ ─ ─ ─ ─ ─ ─ │ simulate | indexer | API  │    │ PVC 20Gi  │
 └───────────────────────┘   only          │ SQLite PVC 1Gi            │    └──────────┘
                                           └──────────────────────────┘
                                                      │ optional, redacted
                                                      ▼
                                                Groq (free tier)
```

## Deploy

Needs `kubectl` pointed at the cluster and about 4 GiB of free memory for
Ollama. Everything is checked by `preflight`, which changes nothing.

```bash
# 0. Get the code (the scripts live in the repo)
git clone -b feat/ai-triage-service https://github.com/Willey2003/ai-soc-lab.git
cd ai-soc-lab

# 1. Secrets (git-ignored). TRIAGE_API_KEY is generated for you; nothing else is
#    needed for the default simulate mode.
cp k8s/triage/secrets.env.example k8s/triage/secrets.env

# 2. Check permissions, storage and the plan
./scripts/k8s-triage.sh preflight

# 3. Deploy with the same settings preflight printed
./scripts/k8s-triage.sh up

# 4. Try it
./scripts/k8s-triage.sh demo            # replays 6 sample Wazuh alerts
./scripts/k8s-triage.sh open            # http://localhost:8020/?key=...
```

### Which namespace

| Situation | What the script does |
|---|---|
| You can create namespaces | Creates `soc-triage` with the quota, limit range and deny-by-default network policy. |
| You can't, and `soc-triage` doesn't exist | Stops and prints two options: deploy into an existing namespace, or the exact commands a cluster admin runs once (create `soc-triage`, apply the quota, bind your account to the `admin` role there). |
| An admin created `soc-triage` for you | Uses it; leaves the admin's quota alone. |
| `NAMESPACE=playground` (any existing namespace you can write to) | Shares it without changing what's there: no quota, no namespace-wide network policy, refuses if an object with the lab's names already exists, and every object it creates carries `app.kubernetes.io/part-of=soc-triage`. `down` deletes only those. |

Pass the same `NAMESPACE=...` to every command (`up`, `status`, `demo`, `open`, `down`).

### Storage

With a default StorageClass (or `STORAGE_CLASS=<name>`), Ollama's models and
the triage history live on PersistentVolumeClaims. Without one, the script
switches to `emptyDir` automatically (`STORAGE=ephemeral`): everything works,
but the ~2 GB model is downloaded again and the triage history starts over
whenever a pod is recreated.

Settings live in `k8s/triage/triage.env`: the alert source (`simulate`,
`indexer` or `none`), the indexer URL if you use one (in-cluster
`https://<svc>.<namespace>.svc.cluster.local:9200` or any host the pods can
reach, e.g. Wazuh in Docker on another machine), AI backends, model, minimum
rule level. Edit and re-run `up`; the ConfigMap name changes with its content so the
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
./scripts/k8s-triage.sh down    # asks first; deletes only what the lab created
```

In its own `soc-triage` namespace that is the namespace; in a shared namespace
it's only the objects labelled `app.kubernetes.io/part-of=soc-triage`.
