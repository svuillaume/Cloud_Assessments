# Deploying RCA on Kubernetes

Manifests live in [`k8s/`](k8s/). No Ingress controller, no cert-manager — the app is exposed
directly via a **NodePort** Service on port 30443, reachable at
`https://<any-node-ip>:30443`. HTTPS comes from `entrypoint.sh`'s own self-signed cert flow
(`SELF_SIGNED=true`, same mechanism the standalone Docker deployment uses) rather than any
cluster-level TLS termination — your browser will show a one-time "untrusted certificate"
warning (click Advanced → Proceed) each time the cert is regenerated, which happens on every
pod restart/recreate (the cert lives in the pod's ephemeral `/tmp`, not on the persistent
`rca-cache` volume — see the note in `k8s/deployment.yaml`).

**`k8s/service.yaml` uses NodePort 30443, not the container's native 8443** — 8443 is outside
Kubernetes' default NodePort range (30000–32767). This was tried first and rejected on a real
cluster (`eks_samv`) with `provided port is not in the valid range` — note that
`kubectl apply -f k8s/service.yaml --dry-run=server` did **not** catch this; the port-range
check only fires during real port allocation, not dry-run. 30443 is now the checked-in
default. If your cluster's `--service-node-port-range` has been widened to include 8443 and
you want the container's native port number reflected externally too, change `nodePort: 30443`
back to `8443` in `service.yaml` — but verify with a real (non-dry-run) apply, not just
`--dry-run=server`.

## Prerequisites this repo doesn't control — confirmed missing on a fresh EKS cluster

These aren't part of `k8s/`'s own manifests (they're cluster-level, not namespaced to `rca`),
but a brand-new EKS cluster with no add-ons installed will be missing all three and the PVC
will sit `Pending` forever without them:

1. **EBS CSI driver add-on** — `aws eks create-addon --cluster-name <cluster> --addon-name aws-ebs-csi-driver`.
   Check first with `aws eks list-addons --cluster-name <cluster>`.
2. **`AmazonEBSCSIDriverPolicy` on the node IAM role** — `aws iam attach-role-policy --role-name <node-role> --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy`.
   Without this the CSI controller pods run but every provisioning call fails on AWS auth.
3. **IMDS hop limit ≥ 2 on the worker node EC2 instances** — check with
   `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[0].Instances[0].MetadataOptions'`.
   If `HttpPutResponseHopLimit` is `1` (a common EKS node default), the EBS CSI controller pods
   crash-loop with `no EC2 IMDS role found` — they're one extra network hop from the host as a
   containerized process. Fix with
   `aws ec2 modify-instance-metadata-options --instance-id <id> --http-put-response-hop-limit 2 --http-tokens required`
   (no reboot needed; delete the crash-looping CSI controller pods afterward to force an
   immediate retry instead of waiting out their backoff).

None of the above is `rca`-specific — any workload on the cluster needing a PVC hits the same
wall. Diagnose with `kubectl describe pvc <name> -n <namespace>` — `ExternalProvisioning`
events waiting on `ebs.csi.aws.com` with no matching pods in `kube-system` point straight at #1.

## GitHub Actions CI/CD — deploy from any machine, no local `.env` needed

Two workflows live in `.github/workflows/` at the repo root:

- **`rca-ci.yml`** — automatic on every push/PR touching `cnapp_rca/rca_ui/**`. No AWS or
  FortiCNAPP credentials involved. Syntax-checks `server.js`, shellchecks the deploy/teardown
  scripts, and validates the `k8s/` manifests still `kustomize build` cleanly (this would have
  caught the missing-`namespace.yaml`-in-temp-dir bug that broke `deploy_k8s.sh` earlier).
- **`rca-deploy.yml`** — manual `workflow_dispatch` only, never runs on push. Builds/pushes the
  image to ECR and deploys to the `eks_samv` cluster's `rca` namespace, reading credentials
  from **GitHub Secrets** instead of a local `.env`/`.env.k8s` file:

  ```bash
  gh workflow run rca-deploy.yml -R <owner>/<repo> -f image_tag=<tag>
  ```

  This is the only deploy path that doesn't require the machine running it to have Docker,
  AWS CLI, `kubectl`, or a copy of `.env` — everything runs on GitHub's runners. Trade-off:
  it authenticates as a dedicated, narrowly-scoped IAM user (`gh-actions-rca-deploy`), not
  your own admin credentials — see the workflow file's header comment for exactly what it can
  and can't do (notably: it cannot create the `rca` namespace itself, only manage resources
  inside an already-existing one).

**GitHub Secrets this depends on** (repo → Settings → Secrets and variables → Actions):
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `EKS_CLUSTER_NAME`,
`ECR_REGISTRY`, `LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, and optionally `LW_SUBACCOUNT`.

**Updating the `LW_*` secrets** (e.g. after rotating a FortiCNAPP API key) — `k8s/rca_update_secrets.sh`
pushes fresh values straight to GitHub's encrypted secret store via `gh secret set`:

```bash
k8s/rca_update_secrets.sh                            # pulls LW_ACCOUNT/LW_KEY_ID/LW_SECRET/
                                                       # LW_SUBACCOUNT from rca_ui/.env
LW_KEY_ID=FORTINET_NEW... k8s/rca_update_secrets.sh   # override just one value
```

**Deliberately not** a `workflow_dispatch` input for the credential values themselves —
GitHub Actions workflow inputs are shown in plain text on the run's summary page, visible to
anyone who can view the repo. Since this repo is **public**, passing `LW_KEY_ID`/`LW_SECRET`
as `-f` flags to `gh workflow run` would publish them on every run. `rca_update_secrets.sh`
never touches a workflow run at all — values go straight from your local `.env` to GitHub's
encrypted secret store.

## Automated deploy — `k8s/deploy_k8s.sh`

`deploy_k8s.sh` does everything in the manual **Deploy** section below for you — builds/pushes
the image, applies the namespace, syncs the credentials Secret from `.env`, and
renders/applies the rest of `k8s/` with your real image substituted in at apply time (the
checked-in YAML keeps its `REPLACE_ME` placeholder untouched either way). It lives in `k8s/`
alongside the manifests, but builds from `rca_ui/` (one level up — where `Dockerfile` and
`.env` are) regardless of which directory you run it from:

```bash
export REGISTRY=your-registry.example.com   # required
export IMAGE_TAG=latest                     # optional, default: latest
k8s/deploy_k8s.sh
```

Or put those in a `.env.k8s` file in `rca_ui/` (kept separate from `.env`, which holds
FortiCNAPP credentials, not deploy config) and just run `k8s/deploy_k8s.sh` — it sources that
file if present. The script prints the current `kubectl` context and asks for confirmation
before touching anything, since it's pointed at whatever cluster your kubeconfig currently
targets.

The rest of this doc is the manual walkthrough the script automates — read it if you want to
understand or customize what's happening, or to deploy by hand instead.

## Deploy

Manual walkthrough — run these from `rca_ui/` (`k8s/deploy_k8s.sh` above does this for you):

```bash
# 1. Build and push the image (needs a registry your cluster can actually pull from).
#    If you're building on Apple Silicon (arm64) for an x86_64 node group (the EKS/GKE/AKS
#    default), you MUST pass --platform — a plain `docker build` produces an arm64 image that
#    pulls fine but fails at container start with
#    `no match for platform in manifest` / ImagePullBackOff. Check your nodes' arch first:
#    `kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}'`
docker build --platform linux/amd64 -t <your-registry>/rca-dashboard:latest .
docker push <your-registry>/rca-dashboard:latest

# 2. Edit k8s/deployment.yaml — replace REPLACE_ME/rca-dashboard:latest with the image above

# 3. Create the namespace
kubectl apply -f k8s/namespace.yaml

# 4. Generate the credentials Secret from your existing .env (don't hand-edit
#    k8s/secret.yaml with real values and apply that directly — generate it instead, so
#    credentials never sit in a plaintext file you might commit)
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
# Falls back to ExternalIP if ExternalDNS isn't populated (e.g. non-AWS clusters):
kubectl get nodes -o wide
```

The app is then reachable at `https://<node-fqdn-or-ip>:30443` (self-signed cert — accept the
browser warning) — no DNS or CA-issued cert step needed. Even when node addresses are public
(not every managed cluster's nodes are — check with `kubectl get nodes -o wide`), the node's security
group typically has no inbound rule for arbitrary external traffic by default, only
self-referencing rules for cluster-internal communication. Open it explicitly, scoped as
tight as your access pattern allows:

```bash
aws ec2 authorize-security-group-ingress --group-id <node-sg-id> \
  --protocol tcp --port 30443 --cidr <your-ip>/32
```

If node IPs are private-only, you'll need a jump host/VPN into the cluster's network instead.

## Redeploy after a code change

```bash
docker build --platform linux/amd64 -t <your-registry>/rca-dashboard:vNEXT .
docker push <your-registry>/rca-dashboard:vNEXT
kubectl set image deployment/rca rca=<your-registry>/rca-dashboard:vNEXT -n rca
```

(or update the tag in `k8s/deployment.yaml` and re-run `kubectl apply -k k8s/` if you prefer
keeping the manifest as the source of truth for the current image tag).

## Tear down — `k8s/rca_tear_down.sh`

`rca_tear_down.sh` (lives next to `deploy_k8s.sh` in `k8s/`) automates the three modes below —
prints the current `kubectl` context and asks for confirmation before deleting anything, same
as the deploy script:

```bash
k8s/rca_tear_down.sh              # full teardown (default)
k8s/rca_tear_down.sh --keep-pvc   # keep the namespace + PVC, drop everything else
k8s/rca_tear_down.sh --restart    # just restart the pod(s), nothing removed
```

The manual equivalent of the default (full) mode — cascades to delete the Deployment,
Service, PVC (and its underlying EBS volume, since `gp2`'s reclaim policy is `Delete`), and
Secret in one shot:

```bash
kubectl delete namespace rca
```

Manual equivalents of the narrower modes:

| Goal | Command |
|---|---|
| Remove the app but **keep the PVC** (preserve `cache.json` for a future redeploy) | `kubectl delete deployment,service,secret -n rca -l app=rca` — leave the PVC alone |
| Just restart the pod without removing anything | `kubectl delete pod -n rca -l app=rca` (the Deployment recreates it within seconds) |

Tearing down the namespace does **not** touch anything at the cluster level — the EKS cluster
itself, the `aws-ebs-csi-driver` add-on, the `AmazonEBSCSIDriverPolicy` IAM attachment, and any
security group rule you opened for external access all stay in place, so a later
`k8s/deploy_k8s.sh` doesn't need to repeat the fresh-cluster prerequisites above. `rca_tear_down.sh`
deliberately does **not** touch these either (they're account/cluster-specific, not something
a generic script should guess at) — reverse them manually if you're decommissioning the
cluster entirely:

```bash
aws eks delete-addon --cluster-name <cluster> --addon-name aws-ebs-csi-driver
aws iam detach-role-policy --role-name <node-role> --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy
aws ec2 revoke-security-group-ingress --group-id <node-sg-id> --protocol tcp --port 30443 --cidr <your-ip>/32
```

## Things to know before running this in production

- **Single replica only — do not scale this Deployment.** `server.js` keeps the live cache,
  the manual-refresh-cache cooldown timer, the last-run governance report, and the
  last-uploaded report logo all in plain in-memory JS variables with no shared external
  store. A second replica would have its own independent, inconsistent copy of all of that —
  e.g. one pod could serve a report with yesterday's uploaded logo while another serves one
  with no logo at all, purely depending on which pod a request landed on.
  `k8s/deployment.yaml`'s `replicas: 1` and `strategy: Recreate` are load-bearing, not
  defaults to tune — `Recreate` also avoids a rolling update wedging on the `ReadWriteOnce`
  PVC while the old pod still holds it.
- **`contacts.csv` (visitor registrations) is NOT persisted.** Only `/app/data` (the
  `cache.json` snapshot) is on the `rca-cache` PVC — `contacts.csv` lives at
  `/app/contacts.csv` in the container's ephemeral filesystem and is lost on every pod
  restart/recreate. Fixable with a one-line `server.js` change (move `CONTACTS_CSV`'s path
  under `/app/data`) if you want registrations to survive restarts — not made unprompted
  since it's an app behavior change, not a manifest change.
- **Cold start can take several minutes to show live data.** `loadCacheFromDisk()` serves the
  persisted snapshot immediately on boot, but a full `refreshData()` cycle (the compliance
  scan especially — see `CLAUDE.md`) can take minutes on a large tenant. The `startupProbe`
  gives the process room to come up; readiness isn't gated on that first refresh finishing.
- **Resource limits in `deployment.yaml` are a starting point, not a measured number** —
  headless Chromium (PDF report generation) is the main memory spike; watch actual usage and
  adjust.
- **`securityContext.capabilities` needs `add: ["NET_BIND_SERVICE", "CHOWN"]` alongside
  `drop: ["ALL"]` — dropping ALL with nothing added back breaks the container entirely**,
  confirmed on a live pod (`exec /entrypoint.sh: operation not permitted`, and even
  `exec /bin/sh` fails the same way). This image's `chown`/`node`/`python3` carry file
  capabilities (`setcap`, see `Dockerfile`) — an empty capability bounding set alongside those
  file-capability xattrs EPERMs every exec for the non-root `node` user, not just the setcap'd
  binaries. This mirrors `install.sh`'s Docker flags
  (`--cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN`) — don't strip the `add:` list
  back down to bare `drop: ["ALL"]`.
- **`MOCK_FILE`** isn't wired into the manifests — add it to the Deployment's `env` (not the
  Secret) if you want to run against a static JSON snapshot instead of live FortiCNAPP data.
- **Self-signed TLS only, no auth in front of the Service** — this is the deliberate
  trade-off for simplicity. Traffic is encrypted but the cert isn't CA-issued or verified by
  the browser, so it's not protected against an active MITM. Anyone who can reach
  `https://<node-ip>:30443` can reach the dashboard; the app's own `@fortinet.com`
  email-domain gate (see `CLAUDE.md`'s courtesy-access-gate note) is explicitly *not* real
  access control.
