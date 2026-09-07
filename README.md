# authz-client.go

[![CI](https://github.com/sweetrpg/authz-client.go/actions/workflows/ci.yaml/badge.svg)](https://github.com/sweetrpg/authz-client.go/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/sweetrpg/authz-client.go.svg)](https://img.shields.io/github/license/sweetrpg/authz-client.go.svg)
[![Issues](https://img.shields.io/github/issues/sweetrpg/authz-client.go.svg)](https://img.shields.io/github/issues/sweetrpg/authz-client.go.svg)
[![PRs](https://img.shields.io/github/issues-pr/sweetrpg/authz-client.go.svg)](https://img.shields.io/github/issues-pr/sweetrpg/authz-client.go.svg)
[![Dependabot](https://badgen.net/github/dependabot/sweetrpg/authz-client.go)](https://badgen.net/github/dependabot/sweetrpg/authz-client.go)

Shared identity resolution and authorization client for SweetRPG's Go APIs: verifies bearer
tokens against `auth-api` (`POST /authz/check`), resolves the subject to the canonical
`users._id` via `users-api` (`GET /profile`), and exposes Gin middleware (`ResolveViewer`,
`RequireAnyRole`) that stashes the identity in the request context alongside `Viewer(c)`,
`Roles(c)`, `Subject(c)`, and `Token(c)` accessors.

## Install

```bash
go get github.com/sweetrpg/authz-client.go
```

## Documentation

Package documentation: [pkg.go.dev/github.com/sweetrpg/authz-client.go](https://pkg.go.dev/github.com/sweetrpg/authz-client.go).
Test coverage reports are published to [sweetrpg.github.io/authz-client.go](https://sweetrpg.github.io/authz-client.go)
on every merge to `develop`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and
[RELEASE.md](RELEASE.md) for how versions get cut.