# Releasing

Releases are driven by GitHub Actions from the `sweetrpg/github-actions` reusable workflows.
All artifacts (workflows, `go.mod`, CI) are versioned; this document explains how a new version
of the library is cut.

## When to release

Publish a new version whenever `develop` accumulates changes intended for consumers - a fix,
a new middleware, or a contract change that API services need. Keep `master` as the single
source of released truth.

## How to release

1. On the `develop` branch, trigger the `Prepare Release` workflow
   ([workflow_dispatch](https://github.com/sweetrpg/authz-client.go/actions/workflows/prepare-release.yaml)).
2. The current version is computed from the previous semver tag, the next version comes from
   git history via [git-cliff](https://git-cliff.org) (conventional commits). The workflow
   opens a `release/<version>` pull request into `master`.
3. Merge the release PR. `tag-release.yaml` runs on the merge to `master` and tags it
   `v<version>` (with `--force` to guard against reruns).
4. Tagging triggers `release.yaml`: re-runs tests, creates a GitHub Release with the changelog,
   and merges `master` back into `develop`.

## Versioning

All versions remain `0.x` until the platform reaches production. Patch, minor, and major bumps
are computed from commit types (`fix` = patch, `feat` = minor, `!`/breaking = major), but a
breaking change must also be a deliberate, coordinated platform change - do not release one
without checking the dependents.

## After the release

Consumers upgrade by bumping the module version in their `go.mod`:

```bash
go get github.com/sweetrpg/authz-client.go@vX.Y.Z
go mod tidy
```