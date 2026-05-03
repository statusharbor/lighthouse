# Contributing to Lighthouse

Thanks for your interest! Lighthouse is the open-source agent half of
Status Harbor — the Console it talks to remains private, but the agent
itself is Apache 2.0 and we welcome PRs.

## Local development

```bash
git clone https://github.com/statusharbor/lighthouse.git
cd lighthouse
go test ./...
```

Most tests use an in-process HTTP mock of the Console — they're fast
(~ms) and require no external services. Cross-repo smoke tests against
a real Console live in the Status Harbor backend repo (private).

## TDD discipline

Each meaningful behaviour change starts with a failing test, then the
implementation lands until it goes green. See `internal/agent/*_test.go`
for the prevailing pattern.

## Pull requests

- Keep PRs focused — one logical change per PR.
- Run `go test ./...` and `go vet ./...` before pushing.
- New public APIs need doc comments and at least one test.
- Sign your commits with the Developer Certificate of Origin
  (`git commit -s`). By signing you assert you wrote the code or
  otherwise have the right to submit it under Apache 2.0.

## Releases

Releases are tagged `vX.Y.Z` and built by GitHub Actions via
`goreleaser`. Every binary is signed with Sigstore cosign and ships
with a SPDX SBOM produced by `syft`. See `.github/workflows/release.yml`.

## Code of conduct

By participating in this project you agree to abide by the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
