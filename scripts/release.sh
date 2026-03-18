#!/usr/bin/env bash
# release.sh — Build, tag, and publish a RitAPI Advanced release
#
# Usage:
#   bash scripts/release.sh [--version X.Y.Z]
#
# If --version is omitted, reads from pyproject.toml.
#
# What it does:
#   1. Reads version from pyproject.toml (or --version flag)
#   2. Runs lint + tests
#   3. Builds .deb package
#   4. Commits any uncommitted changes (prompts first)
#   5. Creates annotated git tag
#   6. Pushes commit + tag
#   7. Creates GitHub Release with auto-generated notes
#   8. Uploads .deb to the release

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version X.Y.Z]" >&2; exit 1 ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION=$(grep '^version' pyproject.toml | head -1 | grep -oP '"\K[^"]+')
fi

TAG="v${VERSION}"
DEB_NAME="ritapi-advanced_${VERSION}_$(dpkg --print-architecture).deb"

echo "=== RitAPI Advanced Release — ${TAG} ==="
echo ""

# ---------------------------------------------------------------------------
# 1. Preflight checks
# ---------------------------------------------------------------------------
echo "[1/8] Preflight checks..."

if ! command -v gh &>/dev/null; then
    echo "ERROR: gh (GitHub CLI) is required. Install: https://cli.github.com" >&2
    exit 1
fi

if git tag -l "$TAG" | grep -q "$TAG"; then
    echo "ERROR: Tag ${TAG} already exists. Bump the version or delete the tag." >&2
    exit 1
fi

echo "      Version: ${VERSION}"
echo "      Tag:     ${TAG}"
echo ""

# ---------------------------------------------------------------------------
# 2. Lint
# ---------------------------------------------------------------------------
echo "[2/8] Running lint..."
if command -v ruff &>/dev/null; then
    ruff check app/ tests/
    echo "      Lint: OK"
else
    echo "      Lint: SKIPPED (ruff not found)"
fi

# ---------------------------------------------------------------------------
# 3. Tests
# ---------------------------------------------------------------------------
echo "[3/8] Running tests..."
python -m pytest tests/ -q
echo "      Tests: OK"

# ---------------------------------------------------------------------------
# 4. Build .deb
# ---------------------------------------------------------------------------
echo "[4/8] Building .deb package..."
bash scripts/build_deb.sh --version "$VERSION"
echo "      .deb: dist/${DEB_NAME}"

# ---------------------------------------------------------------------------
# 5. Stage and commit if needed
# ---------------------------------------------------------------------------
echo "[5/8] Checking for uncommitted changes..."
if [ -n "$(git status --porcelain | grep -v __pycache__)" ]; then
    echo "      Uncommitted changes detected:"
    git status --short | grep -v __pycache__
    echo ""
    read -rp "      Commit these changes before release? [y/N] " confirm
    if [[ "${confirm}" == [yY] ]]; then
        git add -A ':!*__pycache__*'
        git commit -m "chore: pre-release cleanup for ${TAG}"
    else
        echo "      Skipping commit. Tagging current HEAD."
    fi
else
    echo "      Working tree clean."
fi

# ---------------------------------------------------------------------------
# 6. Tag
# ---------------------------------------------------------------------------
echo "[6/8] Creating tag ${TAG}..."
git tag -a "$TAG" -m "${TAG} — $(head -1 CHANGELOG.md | sed 's/^# //')"
echo "      Tag created."

# ---------------------------------------------------------------------------
# 7. Push
# ---------------------------------------------------------------------------
echo "[7/8] Pushing to origin..."
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git push origin "$BRANCH"
git push origin "$TAG"
echo "      Pushed ${BRANCH} + ${TAG}."

# ---------------------------------------------------------------------------
# 8. GitHub Release
# ---------------------------------------------------------------------------
echo "[8/8] Creating GitHub Release..."
gh release create "$TAG" \
    "dist/${DEB_NAME}" \
    --title "${TAG}" \
    --generate-notes \
    --latest

RELEASE_URL=$(gh release view "$TAG" --json url --jq '.url')

echo ""
echo "==========================================="
echo "  Release ${TAG} published!"
echo "  ${RELEASE_URL}"
echo "  .deb: ${DEB_NAME}"
echo "==========================================="
