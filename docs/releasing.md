# Releasing `@vieko/pi-redact`

Releases are tag-driven. Pushing a `vX.Y.Z` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml): the gate,
then `npm publish` over OIDC trusted publishing (no token, no OTP, with
provenance), then the GitHub release.

The unscoped name `pi-redact` belongs to another npm user; this package is
scoped. `publishConfig` sets `access: public` and the public registry, so a
plain `npm publish` works even where installs go through a proxy registry.

## One-time setup

The package must exist before npm accepts a trusted publisher, so the first
version is published by hand from a clean checkout with the gate green:

```bash
npm login --registry https://registry.npmjs.org
git checkout v0.1.1
npm ci && npm run check
npm publish            # OTP applies here, once
git checkout main
```

Then on npmjs.com: **@vieko/pi-redact** -> Settings -> **Trusted Publisher**
-> GitHub Actions. User `vieko`, repository `pi-redact`, workflow
`release.yml`, environment blank.

## Cut a release

```bash
npm version <patch|minor|major> --no-git-tag-version
npm run check
git commit -am "chore: vX.Y.Z" && git push
git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
gh run watch
```

The tag must equal `package.json`'s version; the workflow checks. If the
version is already on the registry (a manual publish), the workflow skips
`npm publish` and still cuts the GitHub release.

## Installing a fresh release

npm's `min-release-age` cooldown blocks a just-published version:

```bash
NPM_CONFIG_MIN_RELEASE_AGE=0 pi update --extensions
```
