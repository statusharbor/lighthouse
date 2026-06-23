# Lighthouse — private network monitoring agent for Status Harbor

Lighthouse is a single static binary you run **inside your private
network** to monitor services that the public internet can't reach. It
talks to your Status Harbor Console over outbound HTTPS only — no inbound
ports, no VPN, no reverse tunnel.

## Install

### Linux / macOS

```bash
curl -fsSL https://lighthouse.statusharbor.io/install.sh \
  | LIGHTHOUSE_TOKEN=<token-from-console> sh
```

The install script downloads the latest signed release binary, writes a
minimal `lighthouse.yaml`, and starts the agent under your service
manager (systemd on Linux; manual start on macOS — launchd plist
generation is on the roadmap).

### Windows

A signed Windows binary is published on every release. Download
`lighthouse_windows_amd64.exe` (or `_arm64.exe`) from
[GitHub Releases](https://github.com/statusharbor/lighthouse/releases/latest),
verify the checksum, then run from a directory you control:

```powershell
$env:LIGHTHOUSE_TOKEN = "<token-from-console>"
.\lighthouse_windows_amd64.exe -config lighthouse.yaml
```

For a long-running service, register it with NSSM or
[`sc.exe create`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create).

### Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to GitHub
Container Registry on every release: `ghcr.io/statusharbor/lighthouse`.
The image is Alpine-based, runs as a non-root user (uid `10001`), and
has no shell entrypoint — pass flags directly to `docker run`.

Three ways to provide config:

**1. Environment variable only (simplest, no YAML required):**

```bash
docker run -d --name lighthouse \
  -e LIGHTHOUSE_TOKEN=<token-from-console> \
  -v lighthouse-data:/var/lib/lighthouse \
  ghcr.io/statusharbor/lighthouse:latest
```

**2. Mounted YAML config:**

```bash
docker run -d --name lighthouse \
  -v /host/path/lighthouse.yaml:/etc/lighthouse/lighthouse.yaml:ro \
  -v lighthouse-data:/var/lib/lighthouse \
  ghcr.io/statusharbor/lighthouse:latest
```

**3. YAML for tuning + env var for the token** (env wins on conflict):

```bash
docker run -d --name lighthouse \
  -v /host/path/lighthouse.yaml:/etc/lighthouse/lighthouse.yaml:ro \
  -v lighthouse-data:/var/lib/lighthouse \
  -e LIGHTHOUSE_TOKEN=<token-from-console> \
  ghcr.io/statusharbor/lighthouse:latest
```

The `lighthouse-data` named volume persists the offline buffer across
container restarts; without it, results captured during a Console outage
are lost when the container is recreated.

### Kubernetes

Two install paths live in the [`deploy/`](./deploy) directory.

**Plain manifest** (`deploy/k8s/lighthouse.yaml`) — single self-contained
file: `Namespace`, `Secret`, `ServiceAccount`, `StatefulSet` with a 5 Gi
`PersistentVolumeClaim` for the offline buffer:

```bash
kubectl create namespace lighthouse
kubectl create secret generic lighthouse-token \
  -n lighthouse --from-literal=token=<token-from-console>
kubectl apply -f https://raw.githubusercontent.com/statusharbor/lighthouse/main/deploy/k8s/lighthouse.yaml
```

**Helm chart** — recommended for anything beyond a quick try. Exposes
resources, persistence size/class, nodeSelector, tolerations, and an
inline structured `agent` config block.

The chart is published as an OCI artifact to GitHub Container Registry
on every release (no `helm repo add` step needed):

```bash
helm install lighthouse oci://ghcr.io/statusharbor/charts/lighthouse \
  --version <ver> \
  --namespace lighthouse --create-namespace \
  --set token=<token-from-console>
```

Or install directly from a local checkout (`deploy/helm/lighthouse/`):

```bash
helm install lighthouse deploy/helm/lighthouse \
  --namespace lighthouse --create-namespace \
  --set token=<token-from-console>
```

For production, prefer an out-of-band secret (External Secrets, Sealed
Secrets, Vault) and reference it instead of inlining the token:

```bash
helm install lighthouse deploy/helm/lighthouse \
  --namespace lighthouse --create-namespace \
  --set existingSecret.name=lighthouse-token \
  --set existingSecret.key=token
```

See [`deploy/helm/lighthouse/values.yaml`](./deploy/helm/lighthouse/values.yaml)
for the full list of tunables.

#### Health probes

When `agent.health_port` is set (the chart defaults it to `9093`), the
agent serves Kubernetes-friendly endpoints:

- `GET /healthz/live` — `200` while the most-recent successful Console
  heartbeat is within ~45 s; `503` once stale (kubelet restarts the pod).
- `GET /healthz/ready` — `200` once initial registration completes; `503`
  before. Readiness is sticky: a transient Console outage does **not**
  flip readiness back, because the agent keeps running checks and
  buffering locally.

Set `healthz.enabled: false` (Helm) or remove the `health_port` from the
ConfigMap (plain YAML) to disable the listener for bare-metal-style
deploys that don't need it.

#### Scaling and high availability

**Run exactly one lighthouse per token.** Two agents sharing the same
token post duplicate check observations to the Console — every
transition is reported twice, often with slightly different timestamps,
which produces flapping state. The Helm chart enforces `replicaCount:
1` and refuses to install otherwise.

The StatefulSet's `OrderedReady` update strategy already handles the
common cases safely:

- **Rolling updates** terminate the old pod before creating the new one
  — no overlap window.
- **Pod restarts** (liveness probe failures, OOMKills) recreate the
  same pod; brief downtime, never duplication.
- **Node failure**: K8s does *not* schedule a replacement pod until the
  old one is confirmed gone. You'll see ~5 minutes of "0 lighthouses"
  during a hard node loss, which is the safe behavior for this app —
  better than 2 racing each other.

What's **not** protected:

- `kubectl scale --replicas=N` directly against the StatefulSet (the
  Helm chart would reject this on next `helm upgrade`, but a raw
  `kubectl scale` slips through).
- Multiple Helm releases or manifests deployed with the same token.
- Running the binary on a VM *and* in a cluster with the same token.

If you need horizontal scale (multiple lighthouses watching different
network segments), install the chart multiple times — one release per
network, each with its own token from the Console:

```bash
helm install lighthouse-vpc-east deploy/helm/lighthouse \
  --namespace lighthouse-vpc-east --create-namespace \
  --set token=<token-east>
helm install lighthouse-vpc-west deploy/helm/lighthouse \
  --namespace lighthouse-vpc-west --create-namespace \
  --set token=<token-west>
```

Each release is an independent lighthouse on the Console with its own
checks, buffer, and identity.

#### PodDisruptionBudget and NetworkPolicy

Both ship with the Helm chart but are **off by default**. They're
enough about your cluster's policies that opting in deliberately is
better than picking opinions for you.

- **`podDisruptionBudget.enabled: true`** blocks voluntary disruptions
  (node drains, cluster-autoscaler scale-down) so the agent keeps
  running through scheduled maintenance. Default would block ops
  drains; only enable if uninterrupted monitoring is more important
  than letting the cluster admin drain a node.
- **`networkPolicy.enabled: true`** lays down a deny-by-default
  ingress/egress policy. Built-in egress allows DNS + outbound TCP 443
  (Console + HTTPS targets). Add `additionalEgress` rules for any
  internal service your checks target (databases, internal HTTP, TCP
  services on non-443 ports). Without those rules, those checks will
  silently fail.

## Configuration

`lighthouse.yaml` (written by `install.sh`):

```yaml
# Required.
token: lh_xxx_yyy_zzz

# Optional. Defaults shown.
agent:
  data_dir: /var/lib/lighthouse
  max_concurrent_checks: 10
  log_level: info
  health_port: 0          # 0 disables; set to e.g. 9093 for K8s probes
```

### Environment-variable overrides

Several fields can be set via env vars; the env value wins over YAML.
This makes container/k8s deploys workable without mounting a config
file:

| Env var                | YAML field        | Notes                                       |
|------------------------|-------------------|---------------------------------------------|
| `LIGHTHOUSE_TOKEN`     | `token`           | Required (one of YAML or env must be set)   |
| `LIGHTHOUSE_DATA_DIR`  | `agent.data_dir`  | Override the offline-buffer location        |
| `LIGHTHOUSE_LOG_LEVEL` | `agent.log_level` | `info` (default) or `debug`                 |

If you see `event buffer disabled (data dir not writable)` in the logs,
the agent can't create `/var/lib/lighthouse` — set `LIGHTHOUSE_DATA_DIR`
to a writable path (e.g. `~/.lighthouse` for dev) or set
`agent.data_dir` in YAML.

The Console URL is **hardcoded** in the binary
(`https://lighthouse.statusharbor.io`). The agent never persists or
transmits its `lighthouse_id` — the server resolves it from the token.

## What it does

- Runs HTTP, HTTPS, TCP, and UDP checks against any service reachable
  from the agent's host.
- Reports state transitions only (edge-triggered) — silent during steady
  state, immediately reports up→down and down→up.
- Heartbeats every 15 seconds so the Console knows it's alive.
- Buffers results to local disk if the Console is unreachable; flushes
  on reconnect.

## Verifying release artifacts

Every binary on the GitHub Releases page is signed with Sigstore cosign
and accompanied by a Software Bill of Materials. To verify a downloaded
binary:

```bash
cosign verify-blob \
  --certificate lighthouse_linux_amd64.cert \
  --signature  lighthouse_linux_amd64.sig \
  --certificate-identity-regexp 'https://github.com/statusharbor/lighthouse' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  lighthouse_linux_amd64
```

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md). Please do not file public issues for
vulnerabilities.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

Apache 2.0 — see [`LICENSE`](./LICENSE).
