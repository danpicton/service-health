# Image release workflow

## First public publication

The intended source repository is `github.com/danpicton/service-health`, and
the image target in the workflow is `ghcr.io/danpicton/service-health`. Keep
those two names aligned. GitHub provides standard hosted Actions runners at no
charge for public repositories. A public GHCR package allows the cluster to
pull the image without registry credentials. Repository and package visibility
are separate settings.

Before creating the repository, review the files that Git would publish. This
checkout may not yet contain Git history; initialize it only if `git status`
reports that it is not a repository. Do not force-add ignored files.

```sh
git init -b main                 # only when this directory is not a Git repository
git add .
git diff --cached --name-only    # review the complete public file list
git diff --cached --check
git commit -m "Prepare public service-health repository"
gh repo create danpicton/service-health --public --source=. --remote=origin --push
```

The first push of `main` does not publish an image. Once the public repository
and its Actions checks are verified, publish a reviewed commit with a stable
version tag that matches `pyproject.toml`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release job builds and pushes the image, then records its immutable digest
in the run summary. GHCR initially creates a personal-account package as
**private**, even when the source repository is public. After the first release,
open the `service-health` package on the `danpicton` GitHub profile, then use
**Package settings → Danger Zone → Change visibility → Public**. Check that
the package is public and anonymously pullable before selecting its digest in
the infrastructure repository. GitHub states that a public package cannot be
made private again; review the image contents and build metadata first.

Do not add actual hostnames, runtime catalogs, scanner reports, caches, or
credentials to this repository or image. They are supplied by the separate
infrastructure deployment at runtime; see [integration](integration.md).

`.github/workflows/release.yml` runs the documented offline unit tests, Ruff
checks, and a `linux/amd64` image build for pull requests. Pull-request jobs
have read-only repository permissions, do not log in to GHCR, and set
`push: false`. A pushed stable version tag (`vMAJOR.MINOR.PATCH`) matching
`pyproject.toml` runs the same checks, then publishes the image. Tags such as
`v0.1.0-rc1` fail validation. The publishing job alone receives
`contents: read` and `packages: write`; it uses its short-lived `GITHUB_TOKEN`.
The workflow does not deploy or access cluster credentials.

The proposed package name is `ghcr.io/danpicton/service-health`. Confirm that
the selected repository has rights to create or update that package before
using the release path. If the actual repository/package owner differs, review
and change the image name in the workflow and these instructions before pushing
a release tag. A maintainer prepares a release by changing the project version,
running the local checks and image smoke test in [README](../README.md), then
pushing an explicit matching tag from an approved release commit. Tag creation
and pushing require operator authorization; this repository has not published
an image.

The release has two tags: the version (for example `v0.1.0`) and the full commit
identifier prefixed with `sha-`. It has OCI `source`, `revision`, and `version`
labels. BuildKit attaches an SBOM and max-level build provenance to the pushed
image. These attestations and labels contain inspectable build metadata;
max-level provenance can expose build argument values. The Dockerfile does not
use build arguments or copy runtime catalogs, credentials, caches, or local
state. Review changes to the Dockerfile and `.dockerignore` before release.
Buildx must support registry attestations; the workflow pushes directly to GHCR
so attestations are retained. No separate GitHub artifact attestation or OIDC
token permission is requested.

The publishing step writes `ghcr.io/danpicton/service-health@sha256:...` to
the workflow run summary. Copy that complete digest reference into the
infrastructure deployment, after reviewing the run and package. To retrieve
the top-level digest later, use the tag from an authorized release:

```sh
docker buildx imagetools inspect ghcr.io/danpicton/service-health:v0.1.0
```

Read the `Digest: sha256:...` field and deploy
`ghcr.io/danpicton/service-health@sha256:...`. For a private package,
authenticate the inspecting workstation first. Pinning this digest avoids
depending on a mutable tag. Keep the prior image available for deliberate
rollback; a database migration may also require restoring a compatible SQLite
backup. Publishing an image does not deploy it.

Repository visibility and GHCR package visibility are separate operator
decisions. A public GHCR package allows anonymous pulls and is the simple
option for the home server. A private package needs operator-provisioned image
pull authentication in the infrastructure repository. Inspect both settings
before release; this workflow changes neither setting. The package can inherit
repository access permissions when linked by the OCI source label, subject to
the owner's package settings, but this does not make package visibility public.

References: [GitHub package permissions](https://docs.github.com/en/packages/managing-github-packages-using-github-actions-workflows/publishing-and-installing-a-package-with-github-actions),
[GHCR visibility and access](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility),
and [Docker attestations](https://docs.docker.com/build/ci/github-actions/attestations/).
