# Contributing

Thank you for contributing to `authz-client.go`! This library is shared infrastructure - the
identity-resolution and role-gating client every SweetRPG Go API uses - so changes here ripple
across `game-room-api`, `game-systems-api`, `catalog-api`, `admin-api`, and `auth-api`. Read
this before opening a PR.

## Lifecycle

1. **Branches.** Create a `feature/*` or `fix/*` branch from `develop`. Hotfixes branch from
   `master`.
2. **Develop.** Make your changes with all local checks green (below).
3. **PR.** Open a pull request targeting `develop` with a Conventional Commits title
   (`feat(scope): description`). The checks in `pr.yaml` must pass.
4. **Merge.** Squash-merge into `develop`; `ci.yaml` runs the full suite against the merged
   state.
5. **Release.** Releasing is done by a maintainer; see `RELEASE.md`.

## Local checks

From the repository root:

```bash
go build -v ./...
go vet ./...
go test -v -coverprofile coverage.out ./...
```

Workflow runs are stricter: `pr.yaml` enforces `gofmt`, `go vet`, `golangci-lint`, and
`go test -race ./...`.

## Commit conventions

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/) so
`prepare-release.yaml` can compute the next version from git history:

```
<type>(<scope>): <description>
```

Types: `feat` (minor bump), `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `revert`. The `<scope>` names the affected area, e.g. `authz`.

## Code of conduct

Behave per `CODE_OF_CONDUCT.md`. Security issues go to `SECURITY.md`, not the issue tracker.