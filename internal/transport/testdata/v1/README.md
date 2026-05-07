# Lighthouse `/v1/` Wire Fixtures (vendored)

Canonical JSON examples for every `/api/lighthouse/v1/*` request and
response body. **Authoritative copy lives in the `status-harbor`
repo** at `tests/wire/v1/`; this directory is a vendored mirror so
the agent's transport tests can verify its decoder accepts what the
Console sends.

When the wire shape changes (rare — `/v1/` is supposed to be stable
per [`docs/LIGHTHOUSE_API.md`](https://github.com/statusharbor/status-harbor/blob/master/docs/LIGHTHOUSE_API.md)),
update both copies. A field added to one side without the matching
update in the other will fail the wire test in the lagging repo.

See `wire_test.go` (sibling to this dir) for the round-trip test.
