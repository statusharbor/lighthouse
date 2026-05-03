# Lighthouse — private network monitoring agent for Status Harbor

Lighthouse is a single static binary you run **inside your private
network** to monitor services that the public internet can't reach. It
talks to your Status Harbor Console over outbound HTTPS only — no inbound
ports, no VPN, no reverse tunnel.

> **Status:** pre-release. The Console-side ingress is at
> `https://lighthouse.statusharbor.io`. Early access is gated per team
> from your account settings.

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
```

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
