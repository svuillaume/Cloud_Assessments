# Deploying RCA on Kubernetes

Manifests live in [`k8s/`](k8s/). No Ingress, no cert-manager — exposed via a **NodePort**
Service with a self-signed TLS cert, single replica only.

## Quick start

| I want to... | Run |
|---|---|
| **Deploy** (any machine — no local Docker/AWS/`.env` needed) | `gh workflow run rca-deploy.yml -R svuillaume/Cloud_Assessments -f image_tag=latest` |
| **Deploy** (this machine — needs Docker + AWS CLI + `.env`) | `k8s/deploy_k8s.sh` |
| **Tear everything down** | `gh workflow run rca-teardown.yml -R svuillaume/Cloud_Assessments -f mode=full` |
| **Restart the pod** | `gh workflow run rca-teardown.yml -R svuillaume/Cloud_Assessments -f mode=restart` |
| **Update FortiCNAPP creds** in GitHub | `k8s/rca_update_secrets.sh` |
| **Watch a workflow run** | `gh run watch <run-id> -R svuillaume/Cloud_Assessments --exit-status` |

**Access:** `https://<node-fqdn-or-ip>:30443` — browser will warn about the self-signed cert
(click Advanced → Proceed).

## Contents

- [How it's exposed](#how-its-exposed)
- [GitHub Actions CI/CD](#github-actions-cicd--recommended) — recommended path
- [Local scripts](#local-scripts--alternative-path)
- [Fresh EKS cluster? Read this first](#fresh-eks-cluster-read-this-first)
- [Production considerations](#production-considerations)

---

## How it's exposed

| | |
|---|---|
| Service type | `NodePort`, port **30443** → container's native **8443** |
| TLS | Self-signed (`SELF_SIGNED=true`, `entrypoint.sh`) — not CA-issued, not cluster-terminated |
| Cert lifetime | Regenerated on **every pod restart** (lives in ephemeral `/tmp`, not the PVC) — expect the browser warning again after each restart |

<details>
<summary><b>Why 30443 and not the container's native 8443?</b></summary>

8443 is outside Kubernetes' default NodePort range (30000–32767). This was tried first and
rejected on a real cluster (`eks_samv`) with `provided port is not in the valid range` —
`kubectl apply -f k8s/service.yaml --dry-run=server` did **not** catch this; the port-range
check only fires during real port allocation, not dry-run. 30443 is the checked-in default.
If your cluster's `--service-node-port-range` has been widened to include 8443, you can change
`nodePort: 30443` back to `8443` in `service.yaml` — verify with a real (non-dry-run) apply.

</details>

---

## GitHub Actions CI/CD — recommended

Three workflows in `.github/workflows/`. `rca-ci.yml` runs automatically; `rca-deploy.yml` and
`rca-teardown.yml` are manual — trigger with `gh workflow run`, or **Actions** tab → workflow
name → **Run workflow** in the GitHub UI.

| Workflow | Trigger | What it does |
|---|---|---|
| `rca-ci.yml` | Automatic (push/PR to `cnapp_rca/rca_ui/**`) | Syntax-checks `server.js`, shellchecks the deploy/teardown scripts, validates `k8s/` still `kustomize build`s cleanly. No credentials involved. |
| `rca-deploy.yml` | Manual | Builds/pushes image to ECR, deploys to `rca` namespace |
| `rca-teardown.yml` | Manual | Removes RCA resources — 3 modes |

### Deploy

```bash
gh workflow run rca-deploy.yml -R svuillaume/Cloud_Assessments -f image_tag=latest
```
`image_tag` is optional (default `latest`) — use a git SHA or version string to avoid
overwriting `latest`.

### Tear down

| Mode | Command | Removes |
|---|---|---|
| `full` (default) | `-f mode=full` | Deployment, Service, Secret, PVC (+ underlying EBS volume) |
| `keep-pvc` | `-f mode=keep-pvc` | Deployment, Service, Secret — **PVC/cached data preserved** |
| `restart` | `-f mode=restart` | Nothing — just recreates the pod |

```bash
gh workflow run rca-teardown.yml -R svuillaume/Cloud_Assessments -f mode=full
```

`full` leaves an empty `rca` namespace behind (see IAM scope note below) — everything with
actual credentials or data in it is gone.

### Watching a run

`gh workflow run` returns immediately with no run ID — grab it right after:

```bash
gh run list -R svuillaume/Cloud_Assessments --limit 1                # get the run ID
gh run watch <run-id> -R svuillaume/Cloud_Assessments --exit-status  # stream until done
```

`rca-deploy.yml`'s last step prints the dashboard's access URL directly in its log
(`gh run view <run-id> -R svuillaume/Cloud_Assessments --log`, or just watch it live).

<details>
<summary><b>IAM scope, GitHub Secrets, and updating credentials</b></summary>

**Auth:** both workflows run as a dedicated IAM user (`gh-actions-rca-deploy`), *not* your
admin credentials — scoped to ECR push on `rca-dashboard` only, plus EKS access limited to
the `rca` namespace. It **cannot create or delete the `rca` namespace object itself**
(cluster-scoped resource, outside a namespace-scoped access policy). The namespace already
exists; if it's ever gone (e.g. a local `rca_tear_down.sh --full`, which *can* delete it),
recreate it once with your own broader access before the next deploy run:
`kubectl apply -f cnapp_rca/rca_ui/k8s/namespace.yaml`. See either workflow file's header
comment for the full IAM policy detail.

**GitHub Secrets required** (repo → Settings → Secrets and variables → Actions):
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `EKS_CLUSTER_NAME`,
`ECR_REGISTRY`, `LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, optionally `LW_SUBACCOUNT`.

**Updating the `LW_*` secrets** (e.g. after rotating a FortiCNAPP API key):

```bash
k8s/rca_update_secrets.sh                            # pulls from rca_ui/.env
LW_KEY_ID=FORTINET_NEW... k8s/rca_update_secrets.sh   # override just one value
```

This is a **local script**, deliberately not a workflow input — GitHub Actions inputs are
shown in plain text on a run's summary page, visible to anyone who can view the repo. Since
this repo is **public**, passing `LW_KEY_ID`/`LW_SECRET` as `-f` flags would publish them on
every run. `rca_update_secrets.sh` sends values straight to GitHub's encrypted secret store
via `gh secret set` — never through a workflow run or its logs.

</details>

---

## Local scripts — alternative path

Needs Docker, AWS CLI, `kubectl`, and `rca_ui/.env` (FortiCNAPP credentials) on the machine
running them.

| Script | Does |
|---|---|
| `k8s/deploy_k8s.sh` | Build, push, apply everything — the local equivalent of `rca-deploy.yml` |
| `k8s/rca_tear_down.sh` | `--full` (default) / `--keep-pvc` / `--restart` — same modes as `rca-teardown.yml` |
| `k8s/rca_update_secrets.sh` | Push `LW_*` values from `.env` to GitHub Secrets |

```bash
export REGISTRY=your-registry.example.com   # required
export IMAGE_TAG=latest                     # optional, default: latest
k8s/deploy_k8s.sh
```
Or put those two vars in `rca_ui/.env.k8s` (separate from `.env`, which holds FortiCNAPP
credentials) and just run `k8s/deploy_k8s.sh` — it sources that file if present. Both scripts
print the current `kubectl` context and ask for confirmation before touching anything.

<details>
<summary><b>Manual walkthrough (what the scripts automate)</b></summary>

Run from `rca_ui/`:

```bash
# 1. Build and push the image. On Apple Silicon (arm64) targeting an x86_64 node group (the
#    EKS/GKE/AKS default) you MUST pass --platform, or the image pulls fine but fails at
#    container start with `no match for platform in manifest` / ImagePullBackOff. Check nodes'
#    arch: kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}'
docker build --platform linux/amd64 -t <your-registry>/rca-dashboard:latest .
docker push <your-registry>/rca-dashboard:latest

# 2. Edit k8s/deployment.yaml — replace REPLACE_ME/rca-dashboard:latest with the image above

# 3. Create the namespace
kubectl apply -f k8s/namespace.yaml

# 4. Generate the credentials Secret from .env (don't hand-edit k8s/secret.yaml with real
#    values and apply that directly — generate it instead, so credentials never sit in a
#    plaintext file you might commit)
kubectl create secret generic rca-credentials -n rca --from-env-file=.env \
  --dry-run=client -o yaml | kubectl apply -f -

# 5. Apply everything else
kubectl apply -k k8s/

# 6. Confirm it's up
kubectl get pods -n rca
kubectl logs -n rca -l app=rca -f

# 7. Find a node's reachable address — prefer the AWS public DNS FQDN (ExternalDNS) over the
#    bare IP: stable across the underlying EC2 instance's public IP changing on stop/start.
kubectl get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="ExternalDNS")]}{.address}{"\n"}{end}{end}'
kubectl get nodes -o wide   # fallback if ExternalDNS isn't populated (e.g. non-AWS clusters)
```

Even when node addresses are public, the node's security group typically has no inbound rule
for external traffic by default — open one scoped as tight as your access pattern allows:

```bash
aws ec2 authorize-security-group-ingress --group-id <node-sg-id> \
  --protocol tcp --port 30443 --cidr <your-ip>/32
```

If node IPs are private-only, you'll need a jump host/VPN into the cluster's network instead.

**Redeploy after a code change:**
```bash
docker build --platform linux/amd64 -t <your-registry>/rca-dashboard:vNEXT .
docker push <your-registry>/rca-dashboard:vNEXT
kubectl set image deployment/rca rca=<your-registry>/rca-dashboard:vNEXT -n rca
```
(or update the tag in `k8s/deployment.yaml` and re-run `kubectl apply -k k8s/`)

**Manual teardown equivalents:**

| Goal | Command |
|---|---|
| Full (`kubectl delete namespace rca`) | Cascades to Deployment, Service, PVC (+ EBS volume), Secret |
| Keep PVC | `kubectl delete deployment/rca service/rca secret/rca-credentials -n rca` — by explicit name, not `-l app=rca`: only the Deployment carries that label, so a selector here would silently leave the Service/Secret behind |
| Restart only | `kubectl delete pod -n rca -l app=rca` |

None of this touches cluster-level resources (the cluster itself, the `aws-ebs-csi-driver`
add-on, the IAM policy attachment, any security group rule) — reverse those manually if
decommissioning the cluster entirely:

```bash
aws eks delete-addon --cluster-name <cluster> --addon-name aws-ebs-csi-driver
aws iam detach-role-policy --role-name <node-role> --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy
aws ec2 revoke-security-group-ingress --group-id <node-sg-id> --protocol tcp --port 30443 --cidr <your-ip>/32
```

</details>

---

## Fresh EKS cluster? Read this first

Not part of `k8s/`'s own manifests (cluster-level, not namespaced to `rca`) — a brand-new EKS
cluster with no add-ons installed is missing all three below, and the PVC will sit `Pending`
forever without them. Not `rca`-specific: any workload needing a PVC hits the same wall.

| # | Check | Fix |
|---|---|---|
| 1 | EBS CSI driver add-on installed? | `aws eks create-addon --cluster-name <cluster> --addon-name aws-ebs-csi-driver` (check first: `aws eks list-addons --cluster-name <cluster>`) |
| 2 | Node IAM role has `AmazonEBSCSIDriverPolicy`? | `aws iam attach-role-policy --role-name <node-role> --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy` — without this, CSI pods run but every provisioning call fails auth |
| 3 | Node IMDS hop limit ≥ 2? | `aws ec2 modify-instance-metadata-options --instance-id <id> --http-put-response-hop-limit 2 --http-tokens required` — check first: `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[0].Instances[0].MetadataOptions'`. Hop limit `1` (a common default) makes CSI controller pods crash-loop with `no EC2 IMDS role found` — they're one extra network hop from the host as a containerized process. No reboot needed; delete the crash-looping pods afterward to force an immediate retry. |

**Diagnose:** `kubectl describe pvc <name> -n <namespace>` — `ExternalProvisioning` events
waiting on `ebs.csi.aws.com` with no matching pods in `kube-system` point straight at #1.

---

## Production considerations

| Constraint | Why |
|---|---|
| **Single replica only — don't scale this Deployment** | `server.js` keeps the live cache, refresh-cooldown timer, last governance report, and last uploaded report logo in plain in-memory JS variables, no shared store. A 2nd replica would serve inconsistent data depending on which pod a request hits. `replicas: 1` + `strategy: Recreate` are load-bearing (`Recreate` also avoids a rolling update wedging on the `ReadWriteOnce` PVC). |
| **`contacts.csv` is NOT persisted** | Only `/app/data` (`cache.json`) is on the PVC — `contacts.csv` is in the container's ephemeral filesystem, lost on every restart. Fixable with a one-line `server.js` change (not made unprompted — app behavior change, not a manifest one). |
| **Cold start can take minutes** | `loadCacheFromDisk()` serves the persisted snapshot immediately, but a full `refreshData()` cycle (compliance scan especially) can take minutes on a large tenant. `startupProbe` gives it room; readiness isn't gated on that first refresh finishing. |
| **Resource limits are a starting point** | Headless Chromium (PDF generation) is the main memory spike — watch actual usage and adjust. |
| **`MOCK_FILE` isn't wired into the manifests** | Add it to the Deployment's `env` (not the Secret) to run against a static snapshot instead of live FortiCNAPP data. |
| **Self-signed TLS, no auth in front of the Service** | Deliberate trade-off. Traffic is encrypted but the cert isn't CA-verified — not MITM-protected. Anyone reaching `https://<node>:30443` reaches the dashboard; the app's `@fortinet.com` email gate is a courtesy lock, not real access control. |

<details>
<summary><b>⚠️ Don't strip <code>securityContext.capabilities.add</code> back to bare <code>drop: ["ALL"]</code></b></summary>

`deployment.yaml` needs `add: ["NET_BIND_SERVICE", "CHOWN"]` alongside `drop: ["ALL"]`.
Dropping ALL with nothing added back **breaks the container entirely** — confirmed on a live
pod (`exec /entrypoint.sh: operation not permitted`, and even `exec /bin/sh` fails the same
way). This image's `chown`/`node`/`python3` carry file capabilities (`setcap`, see
`Dockerfile`) — an empty capability bounding set alongside those file-capability xattrs EPERMs
every exec for the non-root `node` user, not just the setcap'd binaries. This mirrors
`install.sh`'s Docker flags (`--cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN`).

</details>
