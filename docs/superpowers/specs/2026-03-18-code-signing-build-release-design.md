# RitAPI Advanced — Code Signing, Build, Packaging & Release Pipeline
**Date:** 2026-03-18
**Status:** Approved (rev 2)

---

## Overview

Add a complete build, packaging, signing, and release pipeline to RitAPI Advanced. The pipeline produces two signed distribution artifacts (`.deb` and `.tar.gz`) plus a `SHA256SUMS` file, scaffolds `RELEASE_NOTES.md` per release, and publishes to GitHub Releases via CI on every version tag push.

---

## Goals

- Produce installable `.deb` package for Ubuntu 22.04/24.04 deployments
- Produce signed `.tar.gz` tarball as a universal fallback
- GPG-sign all artifacts with a dedicated RitAPI release key
- Automate release publishing via GitHub Actions on `git tag v*`
- Keep local `build.sh` and CI workflow using the same entrypoint (no duplication)
- Use semantic versioning (`v1.0.0`)

---

## Repository Layout

```
final_package/
├── VERSION                              # single source of truth: "1.0.0"
├── build.sh                             # main build script (local + CI entrypoint)
├── RELEASE_NOTES.md                     # scaffolded each release, edited manually
│
├── build/
│   ├── gpg/
│   │   └── gen_signing_key.sh           # one-time: generate dedicated GPG key
│   └── deb/
│       └── DEBIAN/                      # committed to git — permanent package metadata
│           ├── control.tpl              # template; version injected at build time
│           ├── postinst                 # permissions: 0755
│           ├── prerm                    # permissions: 0755
│           └── conffiles
│
├── dist/                                # gitignored — build output
│   ├── ritapi-advanced_1.0.0_amd64.deb
│   ├── ritapi-advanced_1.0.0_amd64.deb.sig
│   ├── ritapi-advanced_1.0.0.tar.gz
│   ├── ritapi-advanced_1.0.0.tar.gz.sig
│   ├── SHA256SUMS
│   └── SHA256SUMS.sig
│
└── .github/
    └── workflows/
        └── release.yml                  # triggers on git tag v*
```

---

## Component: `build.sh`

### Flags
| Flag | Effect |
|---|---|
| `--version <ver>` | Override `VERSION` file (used by CI when tag is pushed) |
| `--skip-sign` | Skip GPG signing (for pre-flight testing without a key) |

### Execution Steps

1. **Read version** — from `VERSION` file or `--version` flag; derive `PKG_NAME=ritapi-advanced`, `PKG_VERSION`, `ARCH=amd64`

2. **Clean `dist/`** — remove previous build output; create fresh `dist/`

3. **Build `.deb`**
   - Create staging tree: `BUILD_STAGE=$(mktemp -d)`
   - Populate `$BUILD_STAGE/opt/ritapi_v_sentinel/` from `projects/ritapi_django/` and `productize/`
   - Populate `$BUILD_STAGE/opt/minifw_ai/` from `projects/minifw_ai_service/`
   - Populate `$BUILD_STAGE/etc/ritapi/` from `productize/config/`
   - Copy `build/deb/DEBIAN/` into `$BUILD_STAGE/DEBIAN/`
   - Inject version: `sed "s/__VERSION__/$PKG_VERSION/" build/deb/DEBIAN/control.tpl > $BUILD_STAGE/DEBIAN/control`
   - Ensure hook permissions: `chmod 0755 $BUILD_STAGE/DEBIAN/postinst $BUILD_STAGE/DEBIAN/prerm`
   - Run: `dpkg-deb --build "$BUILD_STAGE" "dist/${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"`
   - Clean up: `rm -rf "$BUILD_STAGE"`

4. **Build tarball**
   - Create staging dir: `TAR_STAGE=$(mktemp -d)/${PKG_NAME}_${PKG_VERSION}`
   - Mirror same file layout as `.deb` staging into `TAR_STAGE`
   - Include `install_advanced.sh` and `build/deb/DEBIAN/postinst` as `install.sh` at root
   - Run: `tar -czf "dist/${PKG_NAME}_${PKG_VERSION}.tar.gz" -C "$(dirname $TAR_STAGE)" "$(basename $TAR_STAGE)"`
   - Clean up staging dir

5. **Generate `SHA256SUMS`**
   ```bash
   cd dist
   sha256sum "${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb" \
             "${PKG_NAME}_${PKG_VERSION}.tar.gz" > SHA256SUMS
   cd -
   ```

6. **GPG sign** (skipped if `--skip-sign`)
   ```bash
   for artifact in \
       "dist/${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb" \
       "dist/${PKG_NAME}_${PKG_VERSION}.tar.gz" \
       "dist/SHA256SUMS"; do
     gpg --batch --yes --detach-sign --armor --output "${artifact}.sig" "$artifact"
   done
   ```
   `--output` writes directly to `.sig`; no rename step is needed. `--armor` produces
   ASCII-armored output (human-readable, safe in email/paste). `--clearsign` is NOT used —
   all signatures are detached for consistency.

7. **Scaffold `RELEASE_NOTES.md`**
   - Check if `RELEASE_NOTES.md` already contains the header `## v<version>` anywhere
   - If yes: leave the file untouched (developer has already written notes for this version)
   - If no: prepend a new section with version, date, and placeholder bullets

---

## Component: `.deb` Package

### `DEBIAN/control.tpl`
```
Package: ritapi-advanced
Version: __VERSION__
Architecture: amd64
Maintainer: RitAPI Team <support@ritapi.id>
Depends: python3 (>= 3.8), nginx, postgresql, redis-server, nftables, ipset
Description: RitAPI Advanced — AI-assisted API security gateway and enforcement platform
```
`build.sh` replaces `__VERSION__` at build time.

### `DEBIAN/postinst` (permissions: 0755)

The `.deb` places all files into their final locations **before** `postinst` runs. `postinst` must NOT call `install_advanced.sh` (which expects a source tree). Instead it performs only post-placement steps:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Enable and start services
systemctl daemon-reload
systemctl enable ritapi-gunicorn minifw-ai nginx
systemctl start ritapi-gunicorn minifw-ai nginx

# 2. Run Django migrations (DB must already be provisioned)
# Use su rather than sudo — postinst runs as root; sudo may fail in non-login shells
cd /opt/ritapi_v_sentinel
su -s /bin/bash www-data -c "./venv/bin/python manage.py migrate --noinput"
su -s /bin/bash www-data -c "./venv/bin/python manage.py collectstatic --noinput"

echo "[OK] RitAPI Advanced installed. Visit https://<server>/setup to complete setup."
```

> **Note:** Database provisioning (PostgreSQL user/db creation, env file, TLS certs) is still performed by `install_advanced.sh` run separately on first install. The `.deb` is for **upgrades and re-deployments** where infrastructure is already in place. The tarball + `install_advanced.sh` remains the recommended path for **fresh installs**.

### `DEBIAN/prerm` (permissions: 0755)
```bash
#!/usr/bin/env bash
systemctl stop ritapi-gunicorn minifw-ai nginx 2>/dev/null || true
```

### `DEBIAN/conffiles`
```
/etc/ritapi/routing.yml
/etc/ritapi/ritapi.env
/opt/minifw_ai/config/policy.json
```

---

## Component: GPG Signing Key

`build/gpg/gen_signing_key.sh` — run once on the developer machine:

```bash
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: RitAPI Release Signing Key
Name-Email: release@ritapi.id
Expire-Date: 2y
%no-protection
EOF
gpg --armor --export release@ritapi.id > build/gpg/ritapi-release.pub.asc
```

The public key (`ritapi-release.pub.asc`) is committed to the repo so clients can verify downloads.

Export the private key for GitHub:
```bash
gpg --armor --export-secret-keys release@ritapi.id
# Paste output as GitHub Secret: RITAPI_GPG_KEY
```

---

## Component: GitHub Actions Workflow

**File:** `.github/workflows/release.yml`

**Trigger:** `push` on tags matching `v*`

**Runner:** `ubuntu-22.04` (explicit — ensures `dpkg-deb` and GnuPG 2.2+ are available)

### Steps

```yaml
steps:
  - name: Checkout
    uses: actions/checkout@v4

  - name: Import GPG key
    uses: crazy-max/ghaction-import-gpg@v6
    with:
      gpg_private_key: ${{ secrets.RITAPI_GPG_KEY }}
      passphrase: ${{ secrets.RITAPI_GPG_PASSPHRASE }}
      trust_level: ultimate          # sets key to ultimate trust; resolves batch-mode signing failures

  - name: Install dpkg-dev
    run: sudo apt-get install -y dpkg-dev

  - name: Extract version from tag
    run: echo "${GITHUB_REF_NAME#v}" > VERSION

  - name: Build and sign
    run: bash build.sh --version "${GITHUB_REF_NAME#v}"

  - name: Create GitHub Release
    uses: softprops/action-gh-release@v2
    with:
      name: "RitAPI Advanced ${{ github.ref_name }}"
      body_path: RELEASE_NOTES.md
      files: |
        dist/*.deb
        dist/*.deb.sig
        dist/*.tar.gz
        dist/*.tar.gz.sig
        dist/SHA256SUMS
        dist/SHA256SUMS.sig
```

### Required GitHub Secrets
| Secret | Value |
|---|---|
| `RITAPI_GPG_KEY` | `gpg --armor --export-secret-keys release@ritapi.id` |
| `RITAPI_GPG_PASSPHRASE` | Passphrase set during key generation (empty string if `%no-protection` used) |

### Required GitHub Permissions
The workflow job needs `contents: write` to create releases:
```yaml
permissions:
  contents: write
```

---

## Release Workflow (Developer Steps)

```bash
# 1. Update version
echo "1.0.0" > VERSION

# 2. Write release notes (build.sh will not overwrite if ## v1.0.0 header exists)
$EDITOR RELEASE_NOTES.md   # add ## v1.0.0 section

# 3. Commit, tag, push → CI does the rest
git add VERSION RELEASE_NOTES.md
git commit -m "release: v1.0.0"
git tag v1.0.0
git push origin main --tags
```

**Local test build:**
```bash
bash build.sh --skip-sign       # test packaging without GPG
bash build.sh                   # full build + sign locally
```

---

## `.gitignore` Additions

```
# Build output — generated by build.sh
dist/

# Temporary staging directories created inside build/ during packaging
# The permanent build/deb/DEBIAN/ directory is NOT ignored
build/deb/staging/
```

---

## Clarification: Fresh Install vs Upgrade

| Scenario | Recommended method |
|---|---|
| First install on a new server | Run `install_advanced.sh` from the tarball |
| Upgrade existing installation | `dpkg -i ritapi-advanced_<ver>_amd64.deb` |
| Air-gapped / no dpkg | Extract tarball, run included `install.sh` |

---

## Out of Scope

- APT repository hosting (`reprepro`, Cloudsmith, S3-backed apt repo)
- Windows/macOS packaging
- Container image (Docker/OCI) build
- Automated changelog generation from git commits
- Code notarization or Windows Authenticode signing
