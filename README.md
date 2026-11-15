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

**4. With eBPF collectors** (Linux hosts, see [eBPF collectors](#ebpf-collectors)).
eBPF needs root, two capabilities and the host PID namespace, which the
default non-root image does not have:

```bash
docker run -d --name lighthouse \
  --user 0 --pid=host --cap-drop ALL \
  --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
  --cap-add NET_ADMIN --cap-add SYS_RESOURCE \
  -e LIGHTHOUSE_TOKEN=<token-from-console> \
  -v lighthouse-data:/var/lib/lighthouse \
  ghcr.io/statusharbor/lighthouse:latest
```

On kernels before 5.8 replace `--cap-add BPF --cap-add PERFMON` with
`--cap-add SYS_ADMIN`.

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

eBPF collectors run only in the per-node DaemonSet and are switched on
per feature in the Console (the Lighthouse page's "eBPF features"); the
chart grants the privileges with the DaemonSet:

```bash
helm upgrade --install lighthouse oci://ghcr.io/statusharbor/charts/lighthouse \
  --namespace lighthouse --reuse-values --set daemonset.enabled=true
kubectl label namespace lighthouse pod-security.kubernetes.io/enforce=privileged
```

To keep eBPF off the nodes whatever the Console says, add
`--set daemonset.ebpf.enabled=false`. Otherwise the node pods run as root with `BPF`, `PERFMON`, `SYS_PTRACE`,
`DAC_READ_SEARCH`, `NET_ADMIN` and `SYS_RESOURCE` added and `hostPID: true`, and may list pods. The central
StatefulSet stays non-root with all capabilities dropped and never loads
eBPF programs. GKE Autopilot and EKS Fargate do not allow these settings.

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
| `LIGHTHOUSE_EBPF`      | `agent.ebpf`      | `off` is the local eBPF kill switch         |

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
- On Linux, optionally runs eBPF collectors (see below).

## eBPF collectors

Lighthouse can observe the host from the kernel with eBPF: which
processes run in which container and pod, and (as features ship) kernel
events and network quality around an incident. It is off by default and
needs all three of:

1. A Linux host with kernel 5.8 or newer and BTF
   (`/sys/kernel/btf/vmlinux`). On a host without BTF, without the
   capabilities or with kernel lockdown in confidentiality mode, the
   collectors report why they are unsupported and everything else keeps
   working.
2. The privileges: the systemd unit written by `install.sh` already has
   them; for Docker and Kubernetes see the install sections above.
3. The collectors enabled for the Lighthouse in the Console.

The Lighthouse page in the Console shows each collector's state per node
and the reason when it is not running.

**What is collected today:**

- `hello`: the number of process starts on the host.
- `identity`: in the agent's memory only, each process's name,
  executable path, container and pod.
- `incident`: OOM kills and abnormal process exits (command, pid,
  container and pod, signal or exit status, and the pid and command of
  whoever sent a fatal signal), plus counters of failed TCP connects,
  resets and retransmits by peer address and port. Exits with a non-zero
  status are only reported for services, so a failing `grep` stays
  silent.
- `discovery`: the TCP ports processes listen on (port, bind address,
  network namespace, command, executable path, container and pod), read
  once from `/proc` at start and then from the kernel as listeners open
  and close (a listener that lives for less than 15 seconds is not
  reported), and outbound connections counted per source service and
  destination address and port. Never source ports.
- `network`: per source service and destination, smoothed RTT,
  retransmit ratio, connect time and bytes, from the kernel's own TCP
  state; and per DNS resolver, query count, latency and failures, from
  the 12-byte DNS header only (never the names queried or the answers).
- `usage`: per interval, the top 10 processes, containers or services by
  CPU, memory, file I/O, device I/O and network bytes, plus an "other"
  remainder; CPU of processes that start and exit between polls; disk
  latency percentiles per device. The CPU, memory and device I/O part
  reads `/proc` and cgroup files and also runs without eBPF.
- `requests` (off unless OBI is set up): request rate, server-error
  share and latency per service and route for HTTP, gRPC and SQL
  clients, measured by [OpenTelemetry eBPF
  Instrumentation](https://opentelemetry.io/docs/zero-code/obi/) (OBI)
  running as a separate process. Only the service, route template,
  method class, status class and SQL operation type leave the host;
  headers, bodies, query strings, raw paths and SQL text never do. Set
  `agent.obi.path` (or `LIGHTHOUSE_OBI_PATH`) to an OBI binary for the
  agent to supervise; on Kubernetes set `daemonset.obi.enabled` in the
  chart to run it as a second container.
- Traces (with Real traffic, when switched on in the Console): OBI's
  request spans go to the agent on loopback, which keeps only an
  allow-list of attributes (templated routes and paths, status, method,
  database system and operation, exception type, a client span's peer)
  and drops query strings, full URLs, SQL text, headers, bodies,
  exception messages and callers' addresses before anything leaves the
  host. It keeps every failed trace; within 5 spans a second it keeps
  the slowest first, then a sample of the rest. OBI's context
  propagation is always off: the
  agent never writes into your traffic.
- Check traces: each check run becomes a trace with DNS, connect, TLS
  and time-to-first-byte children. An HTTP check with "Send trace
  header" ticked (off by default) adds a W3C `traceparent` header so the
  target's traces continue the check's: Go services under OBI and
  services with an OpenTelemetry SDK do; Python, Node.js and Java
  services under OBI start their own trace, since OBI reads the header
  there only with propagation on.

Command-line arguments, environment variables, file contents and network
payloads are never read. Collector programs are not
pinned, so the kernel removes them when the agent exits. OBI (Real
traffic) pins one map, its trace context, which it would leave behind:
the agent gives it a private directory,
`/sys/fs/bpf/statusharbor-obi-<agent pid>`, and deletes it when OBI
stops (directories of agents that died are swept at the next start).
The Kubernetes sidecar has no host BPF filesystem, so its OBI pins
nothing on the node.

**Switching it off:** disable the collectors in the Console, or set
`LIGHTHOUSE_EBPF=off` (or `agent.ebpf: off`) on the host. The local
setting always wins over the Console and loads nothing.

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
