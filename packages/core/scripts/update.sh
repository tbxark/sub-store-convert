#!/usr/bin/env sh
set -e

ROOT=$(git rev-parse --show-toplevel)
VENDOR="$ROOT/packages/core/src/vendors/Sub-Store"

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

echo "Updated Sub-Store vendor and all package versions to $TAG"

pnpm build:core