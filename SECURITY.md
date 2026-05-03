# Security policy

## Reporting a vulnerability

If you've found a security issue in Lighthouse — the agent binary, the
release pipeline, or how it interacts with the Console — please **do not
file a public GitHub issue**.

Instead, email **security@statusharbor.io**. Encrypted reports are
welcome (PGP key fingerprint published on
https://statusharbor.io/.well-known/security.txt).

We aim to:

- Acknowledge within **2 business days**.
- Provide a remediation plan within **10 business days** for confirmed
  issues.
- Coordinate disclosure within **90 days** of the initial report.

## What's in scope

- The Lighthouse agent binary (this repo).
- The signed release artifacts and their signing pipeline.
- Issues in how the agent handles secrets (tokens, headers, URLs) — see
  the redaction policy below.

## What's out of scope (here)

- The Status Harbor Console / API surface — report at the main support
  channel.
- The hosted ingress at `lighthouse.statusharbor.io` — reach out via
  status-harbor-side responsible disclosure.
- Issues you reproduce only after disabling the redaction policy
  (`unsafe_log_raw: true`).

## Sensitive-data handling

The agent **never logs**:

- URL query strings (stripped to `?...redacted...`).
- Header values for `Authorization`, `Cookie`, `Set-Cookie`,
  `Proxy-Authorization`, or any header name matching `*token*`,
  `*secret*`, `*key*`, `*auth*`, or `*password*` (case-insensitive).
- Request or response bodies (size + content-type only).
- Raw bytes from TCP/UDP probes (length only).

Customers who need verbose logging during deeper troubleshooting can
opt in per check (deferred to v2).
