#!/bin/bash
set -e

VERSION=$1
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 0.2.0)"
    exit 1
fi

echo "=== Creating release v$VERSION ==="

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: Uncommitted changes. Commit or stash first."
    exit 1
fi

# Run tests
echo "Running tests..."
make test

# Run lint
echo "Running lint..."
make lint

# Update version files
echo "$VERSION" > VERSION
sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml

# Commit version bump
git add VERSION Cargo.toml
git commit -m "Release v$VERSION"

# Create and push tag
git tag -a "v$VERSION" -m "Release v$VERSION"
git push origin main
git push origin "v$VERSION"

# Build release artifacts
echo "Building release..."
make app-bundle-signed
make dmg

echo ""
echo "=== Release v$VERSION complete ==="
echo "Artifacts:"
echo "  - out/SecretKeeper.app"
echo "  - out/SecretKeeper-$VERSION.dmg"
echo ""
echo "For production release with ESF:"
echo "  make dmg-prod ESF_SIGNING_IDENTITY=\"Developer ID Application: ...\""
echo "  make notarize"
