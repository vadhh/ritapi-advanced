#!/usr/bin/env bash
# build_deb.sh — Build a self-contained .deb for RitAPI Advanced
#
# Usage:
#   bash scripts/build_deb.sh [--version VERSION] [--output-dir DIR]
#
# Options:
#   --version VERSION   Package version (default: read from pyproject.toml)
#   --output-dir DIR    Where to write the .deb  (default: dist/)
#
# Requirements on build host:
#   sudo apt-get install -y python3.12 python3.12-venv python3-pip \
#       libyara-dev gcc dpkg-dev gzip
#
# The produced .deb:
#   - Installs app + pre-built venv to /opt/ritapi-advanced/
#   - Installs config template to /etc/ritapi-advanced/env  (conffile)
#   - Installs systemd unit to /lib/systemd/system/ritapi-advanced.service
#   - Installs YARA rules to /opt/ritapi-advanced/rules/
#   - Creates system user 'ritapi' and /var/log/ritapi/ on install (postinst)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
VERSION=$(grep '^version' pyproject.toml | head -1 | grep -oP '"\K[^"]+')
OUTPUT_DIR="$REPO_ROOT/dist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)    VERSION="$2";    shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

ARCH=$(dpkg --print-architecture)
PKG_NAME="ritapi-advanced_${VERSION}_${ARCH}"
STAGING="$REPO_ROOT/build/deb-staging/$PKG_NAME"

echo "==> Building ritapi-advanced $VERSION ($ARCH)"
echo "    Staging: $STAGING"
echo "    Output:  $OUTPUT_DIR/$PKG_NAME.deb"

# ---------------------------------------------------------------------------
# 1. Clean staging area
# ---------------------------------------------------------------------------
rm -rf "$STAGING"
mkdir -p "$STAGING"

# ---------------------------------------------------------------------------
# 2. Copy DEBIAN control files
# ---------------------------------------------------------------------------
cp -r "$REPO_ROOT/packaging/DEBIAN" "$STAGING/DEBIAN"

# Substitute placeholders in control file
sed -i "s/ARCH_PLACEHOLDER/$ARCH/g" "$STAGING/DEBIAN/control"
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$STAGING/DEBIAN/control"

# Make maintainer scripts executable (required by dpkg)
chmod 755 "$STAGING/DEBIAN/postinst" \
           "$STAGING/DEBIAN/prerm" \
           "$STAGING/DEBIAN/postrm"

# ---------------------------------------------------------------------------
# 3. Install app files to /opt/ritapi-advanced
# ---------------------------------------------------------------------------
APP_DEST="$STAGING/opt/ritapi-advanced"
mkdir -p "$APP_DEST"

# Copy source code, rules, and operational files
rsync -a --exclude='.venv' --exclude='build' --exclude='dist' \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' \
    --exclude='.env' --exclude='.env.staging.local' \
    --exclude='logs/' --exclude='sbom.json' \
    "$REPO_ROOT/" "$APP_DEST/"

# ---------------------------------------------------------------------------
# 4. Build the virtualenv inside the staging tree
# ---------------------------------------------------------------------------
echo "==> Creating virtualenv and installing dependencies..."
python3.12 -m venv "$APP_DEST/.venv"
"$APP_DEST/.venv/bin/pip" install --quiet --upgrade pip wheel
"$APP_DEST/.venv/bin/pip" install --quiet \
    --require-hashes -r "$REPO_ROOT/requirements.lock"

# Strip test/dev extras from the venv to keep size down
"$APP_DEST/.venv/bin/pip" uninstall -y \
    pytest pytest-anyio anyio pytest-cov \
    locust ruff bandit pip-tools 2>/dev/null || true

# Fix venv shebangs so they work from /opt/ritapi-advanced/.venv
# (the build path is embedded by default; relocate it)
VENV_PYTHON="$APP_DEST/.venv/bin/python3.12"
find "$APP_DEST/.venv/bin" -type f | while read -r f; do
    if file "$f" | grep -q "text"; then
        sed -i "1s|#!.*python.*|#!/opt/ritapi-advanced/.venv/bin/python3.12|" "$f" || true
    fi
done

echo "==> Venv size: $(du -sh "$APP_DEST/.venv" | cut -f1)"

# ---------------------------------------------------------------------------
# 5. Install config template to /etc/ritapi-advanced/
# ---------------------------------------------------------------------------
mkdir -p "$STAGING/etc/ritapi-advanced/policies"
cp "$REPO_ROOT/packaging/etc/ritapi-advanced/env" \
   "$STAGING/etc/ritapi-advanced/env"
cp "$REPO_ROOT/configs/routing.yml" \
   "$STAGING/etc/ritapi-advanced/routing.yml"
cp "$REPO_ROOT/configs/policies/"*.yml \
   "$STAGING/etc/ritapi-advanced/policies/"

# ---------------------------------------------------------------------------
# 6. Install systemd units to /lib/systemd/system/
# ---------------------------------------------------------------------------
mkdir -p "$STAGING/lib/systemd/system"
cp "$REPO_ROOT/packaging/lib/systemd/system/ritapi-advanced.service" \
   "$STAGING/lib/systemd/system/ritapi-advanced.service"
cp "$REPO_ROOT/packaging/lib/systemd/system/minifw-ai.service" \
   "$STAGING/lib/systemd/system/minifw-ai.service"

# ---------------------------------------------------------------------------
# 7. Install docs to /usr/share/doc/ritapi-advanced/
# ---------------------------------------------------------------------------
mkdir -p "$STAGING/usr/share/doc/ritapi-advanced"
cp "$REPO_ROOT/packaging/usr/share/doc/ritapi-advanced/copyright" \
   "$STAGING/usr/share/doc/ritapi-advanced/copyright"

# Compress changelog (Debian policy requires this)
if [ -f "$REPO_ROOT/CHANGELOG.md" ]; then
    gzip -9 -c "$REPO_ROOT/CHANGELOG.md" \
        > "$STAGING/usr/share/doc/ritapi-advanced/changelog.gz"
fi

# ---------------------------------------------------------------------------
# 8. Set permissions
# ---------------------------------------------------------------------------
# All files owned by root in the package (postinst re-owns to ritapi)
find "$STAGING" -not -path "*/DEBIAN/*" | xargs chown root:root 2>/dev/null || true
find "$STAGING" -type d | xargs chmod 755
find "$STAGING" -type f -not -path "*/DEBIAN/*" | xargs chmod 644
# Scripts must be executable
chmod 755 "$APP_DEST/scripts/"*.sh

# ---------------------------------------------------------------------------
# 9. Update Installed-Size in control file
# ---------------------------------------------------------------------------
INSTALLED_KB=$(du -sk "$STAGING" --exclude="$STAGING/DEBIAN" | cut -f1)
sed -i "s/SIZE_PLACEHOLDER/$INSTALLED_KB/" "$STAGING/DEBIAN/control"

# ---------------------------------------------------------------------------
# 10. Build the .deb
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
dpkg-deb --root-owner-group --build "$STAGING" "$OUTPUT_DIR/$PKG_NAME.deb"

echo ""
echo "==> Built: $OUTPUT_DIR/$PKG_NAME.deb"
echo "    Size:  $(du -sh "$OUTPUT_DIR/$PKG_NAME.deb" | cut -f1)"
echo ""
echo "Verify:  dpkg-deb --info $OUTPUT_DIR/$PKG_NAME.deb"
echo "Install: sudo dpkg -i $OUTPUT_DIR/$PKG_NAME.deb"
echo "         sudo apt-get install -f   # fix any missing Depends"
