#!/usr/bin/env sh
set -e

ROOT=$(git rev-parse --show-toplevel)
VENDOR="$ROOT/packages/core/src/vendors/Sub-Store"
CORE_PACKAGE_JSON="$ROOT/packages/core/package.json"
VENDOR_PACKAGE_JSON="$VENDOR/backend/package.json"

if [ -z "$TAG" ]; then
  TAG=$(curl -fsSL https://api.github.com/repos/sub-store-org/Sub-Store/releases/latest | node -e "const fs=require('fs'); const release=JSON.parse(fs.readFileSync(0, 'utf8')); if (!release.tag_name) throw new Error('Missing release tag_name'); console.log(release.tag_name)")
fi

# 1. Switch the submodule to the given tag
git -C "$VENDOR" fetch --tags
git -C "$VENDOR" checkout "tags/$TAG"
git -C "$ROOT" add packages/core/src/vendors/Sub-Store

# 2. Sync every workspace package version to $TAG (preserves JSON formatting, workspace:* deps untouched)
for pkg_json in "$ROOT/package.json" "$ROOT/packages"/*/package.json; do
  pkg=${pkg_json%/package.json}
  (cd "$pkg" && npm pkg set version="$TAG")
done

# 3. Sync existing core dependency versions from Sub-Store backend package.json
node - "$CORE_PACKAGE_JSON" "$VENDOR_PACKAGE_JSON" <<'NODE'
const fs = require('fs');

const [, , corePackagePath, vendorPackagePath] = process.argv;
const corePackage = JSON.parse(fs.readFileSync(corePackagePath, 'utf8'));
const vendorPackage = JSON.parse(fs.readFileSync(vendorPackagePath, 'utf8'));

const vendorVersions = {
  ...vendorPackage.dependencies,
  ...vendorPackage.devDependencies,
  ...vendorPackage.peerDependencies,
  ...vendorPackage.optionalDependencies,
};

for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
  const dependencies = corePackage[section];
  if (!dependencies) continue;

  for (const name of Object.keys(dependencies)) {
    if (vendorVersions[name]) {
      dependencies[name] = vendorVersions[name];
    }
  }
}

fs.writeFileSync(corePackagePath, `${JSON.stringify(corePackage, null, 2)}\n`);
NODE

echo "Updated Sub-Store vendor, package versions, and core dependency versions to $TAG"

pnpm build:core
