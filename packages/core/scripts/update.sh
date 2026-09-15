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

# 3. Sync existing core dependency versions from Sub-Store backend package.json.
#    A locally pinned version is kept when it is newer than Sub-Store's, so upstream never downgrades core.
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

// Parse a semver-ish range (^1.2.3, >=1.2, 1.2.3-beta.1, 1.2.x) into a comparable tuple.
// Returns null for values that carry no version (workspace:*, file:..., git URLs, latest, ...).
function parseVersion(range) {
  const match = /^[\s^~><=v]*(\d+)(?:\.(\d+|[x*]))?(?:\.(\d+|[x*]))?(?:-([0-9A-Za-z.-]+))?/i.exec(String(range).trim());
  if (!match) return null;
  const num = (value) => (value === undefined || value === 'x' || value === '*' ? 0 : Number(value));
  return { major: num(match[1]), minor: num(match[2]), patch: num(match[3]), prerelease: match[4] || '' };
}

function compareVersions(a, b) {
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] > b[key] ? 1 : -1;
  }
  // A release is newer than a prerelease of the same version
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === '') return 1;
  if (b.prerelease === '') return -1;
  return a.prerelease > b.prerelease ? 1 : -1;
}

for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
  const dependencies = corePackage[section];
  if (!dependencies) continue;

  for (const name of Object.keys(dependencies)) {
    const vendorVersion = vendorVersions[name];
    if (!vendorVersion) continue;

    const currentVersion = dependencies[name];
    const current = parseVersion(currentVersion);
    const vendor = parseVersion(vendorVersion);

    if (current && vendor && compareVersions(current, vendor) >= 0) {
      if (currentVersion !== vendorVersion) {
        console.log(`  keep ${section} ${name}@${currentVersion} (sub-store uses ${vendorVersion})`);
      }
      continue;
    }

    if (currentVersion !== vendorVersion) {
      console.log(`  sync ${section} ${name}@${currentVersion} -> ${vendorVersion}`);
    }
    dependencies[name] = vendorVersion;
  }
}

fs.writeFileSync(corePackagePath, `${JSON.stringify(corePackage, null, 2)}\n`);
NODE

echo "Updated Sub-Store vendor, package versions, and core dependency versions to $TAG"

pnpm build:core
