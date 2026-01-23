#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "0.1.0")
DIST_DIR="$PROJECT_ROOT/dist"

# Cleanup function for error handling
cleanup() {
    local exit_code=$?
    if [ -d "$PROJECT_ROOT/debian" ]; then
        echo "Cleaning up debian directory..."
        rm -rf "$PROJECT_ROOT/debian"
    fi
    if [ $exit_code -ne 0 ]; then
        echo "Build failed with exit code $exit_code" >&2
    fi
    exit $exit_code
}
trap cleanup EXIT

echo "Building SecretKeeper Debian package v${VERSION}..."

cd "$PROJECT_ROOT"

# Create dist directory
mkdir -p "$DIST_DIR"

# Check for required tools
if ! command -v dpkg-buildpackage &> /dev/null; then
    echo "Error: dpkg-buildpackage not found. Install with: apt-get install devscripts debhelper" >&2
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Install Rust from https://rustup.rs" >&2
    exit 1
fi

# Build the binary first to verify compilation
echo "Building binary..."
cargo build --release --package secretkeeper-agent

# Verify binary was built
if [ ! -f "target/release/secretkeeper-agent" ]; then
    echo "Error: Binary not found after build" >&2
    exit 1
fi

# Copy debian directory to project root for dpkg-buildpackage
echo "Preparing debian directory..."
cp -r packaging/debian .

# Update version in changelog if needed
# Use sed with backup extension for portability, then remove backup
sed -i.bak "s/^secretkeeper ([^)]*)/secretkeeper (${VERSION}-1)/" debian/changelog
rm -f debian/changelog.bak

# Build the package
echo "Building Debian package..."
dpkg-buildpackage -b -us -uc

# Move generated packages to dist/
echo "Moving packages to dist/..."
mv ../*.deb "$DIST_DIR/" 2>/dev/null || true
mv ../*.changes "$DIST_DIR/" 2>/dev/null || true
mv ../*.buildinfo "$DIST_DIR/" 2>/dev/null || true

# Verify package was created
DEB_COUNT=$(find "$DIST_DIR" -name "*.deb" -type f 2>/dev/null | wc -l)
if [ "$DEB_COUNT" -eq 0 ]; then
    echo "Error: No .deb package was created" >&2
    exit 1
fi

echo ""
echo "Package built successfully!"
echo "Output: $DIST_DIR/"
ls -la "$DIST_DIR/"*.deb
