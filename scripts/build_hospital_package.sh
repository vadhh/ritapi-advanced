#!/usr/bin/env bash
# Build the hospital deployment package for RitAPI Advanced.
# Copies application source into the staging directory, generates metadata, and creates the ZIP.
#
# Run from the repository root:
#   bash scripts/build_hospital_package.sh
#
# Prerequisites: All documentation files in dist/ritapi-advanced-hospital-deployment-v1.4.0/
# must already exist (created by the plan execution steps before this script).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${REPO_ROOT}/dist/ritapi-advanced-hospital-deployment-v1.4.0"
APP_DIR="${PKG_DIR}/01_APPLICATION"
METADATA_DIR="${PKG_DIR}/12_PACKAGING_METADATA"
ZIP_NAME="ritapi-advanced-hospital-deployment-v1.4.0"
ZIP_OUT="${REPO_ROOT}/dist/${ZIP_NAME}.zip"

echo "=== RitAPI Advanced — Hospital Package Builder ==="
echo "Repo root: ${REPO_ROOT}"
echo "Package:   ${PKG_DIR}"
echo

# --- 1. Create 01_APPLICATION structure ---
echo "--- Copying application source ---"

mkdir -p "${APP_DIR}"

rsync -a --delete \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.pytest_cache' \
    "${REPO_ROOT}/app/" "${APP_DIR}/app/"
echo "  app/ copied"

if [[ -d "${REPO_ROOT}/configs" ]]; then
    rsync -a --delete "${REPO_ROOT}/configs/" "${APP_DIR}/configs/"
    echo "  configs/ copied"
fi

if [[ -d "${REPO_ROOT}/docs" ]]; then
    rsync -a --delete "${REPO_ROOT}/docs/" "${APP_DIR}/docs/"
    echo "  docs/ copied"
fi

if [[ -d "${REPO_ROOT}/rules" ]]; then
    rsync -a --delete "${REPO_ROOT}/rules/" "${APP_DIR}/rules/"
    echo "  rules/ copied"
fi

for f in requirements.txt requirements-dev.txt pyproject.toml CHANGELOG.md README.md; do
    if [[ -f "${REPO_ROOT}/${f}" ]]; then
        cp "${REPO_ROOT}/${f}" "${APP_DIR}/${f}"
        echo "  ${f} copied"
    fi
done

# --- 2. Ensure 13_OPTIONAL/docker has copies (already done, but be idempotent) ---
echo
echo "--- Docker files ---"
mkdir -p "${PKG_DIR}/13_OPTIONAL/docker"

for f in Dockerfile docker-compose.yml; do
    if [[ -f "${REPO_ROOT}/${f}" ]]; then
        cp "${REPO_ROOT}/${f}" "${PKG_DIR}/13_OPTIONAL/docker/${f}"
        echo "  ${f} copied"
    fi
done

# --- 3. Copy sbom.json if it exists ---
if [[ -f "${REPO_ROOT}/sbom.json" ]]; then
    cp "${REPO_ROOT}/sbom.json" "${METADATA_DIR}/sbom.json"
    echo "  sbom.json copied"
fi

# --- 4. Make all shell scripts executable ---
echo
echo "--- Setting script permissions ---"
find "${PKG_DIR}" -name "*.sh" -exec chmod +x {} \;
echo "  All .sh files set executable"

# --- 5. Generate package manifest ---
echo
echo "--- Generating package manifest ---"
find "${PKG_DIR}" -type f | sort | sed "s|${PKG_DIR}/||" \
    > "${METADATA_DIR}/package_manifest.txt"
FILE_COUNT=$(wc -l < "${METADATA_DIR}/package_manifest.txt")
echo "  ${FILE_COUNT} files listed in package_manifest.txt"

# --- 6. Generate SHA256SUMS ---
echo
echo "--- Generating SHA256SUMS ---"
cd "${PKG_DIR}"
find . -type f | sort | xargs sha256sum \
    > "${METADATA_DIR}/SHA256SUMS.txt"
echo "  SHA256SUMS.txt generated ($(wc -l < "${METADATA_DIR}/SHA256SUMS.txt") entries)"

# --- 7. Create ZIP ---
echo
echo "--- Creating ZIP archive ---"
cd "${REPO_ROOT}/dist"
rm -f "${ZIP_OUT}"
zip -r "${ZIP_NAME}.zip" "${ZIP_NAME}/" -x "*.DS_Store" -x "*__pycache__*" -x "*.pyc"
ZIP_SIZE=$(du -sh "${ZIP_OUT}" | cut -f1)
echo "  ${ZIP_OUT} (${ZIP_SIZE})"

echo
echo "=== Package build complete ==="
echo "ZIP: ${ZIP_OUT}"
echo "Files: ${FILE_COUNT}"
echo
echo "Verify with:"
echo "  cd ${PKG_DIR} && sha256sum -c 12_PACKAGING_METADATA/SHA256SUMS.txt | grep -v OK"
