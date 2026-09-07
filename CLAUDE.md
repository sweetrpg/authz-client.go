# AGENTS.md

This file provides guidance to Claude Code, Codex, GitHub Copilot, and other AI coding agents
working in this repository.

## About This Project

`authz-client.go` is the shared identity-resolution and authorization client for SweetRPG's Go
APIs. It calls `auth-api`'s `POST /authz/check` to verify a caller's bearer token and resolve
their roles/subject, and `users-api`'s `GET /profile` to resolve that subject to the canonical
`users._id`, then exposes Gin middleware (`ResolveViewer`, `RequireAnyRole`) that stashes the
resolved identity in the request context alongside `Viewer(c)`, `Roles(c)`, `Subject(c)`, and
`Token(c)` accessors.

It exists so the local `authz` packages inside `game-room-api`, `game-systems-api`,
`catalog-api`, and `admin-api` collapse into one place. `auth-api` depends on only the resolver
half (it *is* the `/authz/check` server) and never uses the role middleware.

## Two resolution semantics live here

- `ResolveViewer` treats a missing/invalid token, an auth-api error, or an unresolvable subject
  as an *anonymous* viewer (`""`) rather than aborting — reads must stay accessible to anonymous
  callers. Used by `game-room-api`, `game-systems-api`, and `catalog-api`'s write-route groups.
- `RequireAnyRole` is fail-closed: missing/invalid token -> 401, auth-api unavailable -> 503,
  caller lacking a qualifying role -> 403. Used by role-gated admin routes.

## Dependencies

Depends on `api-core.go` (VO types for error bodies), `common.go` (logging), `gin-gonic/gin`
(middleware), and `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` (outbound
tracing). Depended on by `game-room-api`, `game-systems-api`, `catalog-api`, `admin-api`, and
`auth-api`.

## Committing Code

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

## Branches and Workflow

* `develop` - integration branch, default branch, target for all PRs.
* `master` - latest released state, nothing committed directly.
* `feature/*`, `fix/*` branched from `develop`; `hotfix/*` branched from `master`.

See `CONTRIBUTING.md` for the full workflow.

## Running Checks Locally

```bash
go build -v ./...
go vet ./...
go test -v -coverprofile coverage.out ./...
```

## Releases

See `RELEASE.md`. Summary: trigger `prepare-release.yaml` (`workflow_dispatch` against
`develop`), which computes the next version from conventional commits via git-cliff and opens
a `release/<version>` PR into `master`. Merging that PR tags the release
(`tag-release.yaml`), which triggers `release.yaml` - re-runs tests, creates a GitHub
Release, and merges `master` back into `develop`.