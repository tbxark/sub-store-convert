#!/usr/bin/env sh
set -e

if [ -z "$TAG" ]; then
  echo "Usage: TAG=<version> pnpm run update:vendor" >&2
  exit 1
fi

ROOT=$(git rev-parse --show-toplevel)
VENDOR="$ROOT/packages/core/src/vendors/Sub-Store"

# 1. Switch the submodule to the given tag
git -C "$VENDOR" fetch --tags
git -C "$VENDOR" checkout "tags/$TAG"
git -C "$ROOT" add packages/core/src/vendors/Sub-Store

# 2. Sync every package version to $TAG (preserves JSON formatting, workspace:* deps untouched)
for pkg in "$ROOT" "$ROOT/packages/core" "$ROOT/packages/app" "$ROOT/packages/cli"; do
  (cd "$pkg" && npm pkg set version="$TAG")
done

echo "Updated Sub-Store vendor and all package versions to $TAG"
