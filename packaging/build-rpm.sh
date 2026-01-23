#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "0.1.0")
DIST_DIR="$PROJECT_ROOT/dist"
RPMBUILD_DIR="$PROJECT_ROOT/rpmbuild"

# Cleanup function for error handling
cleanup() {
    local exit_code=$?
    if [ -d "$RPMBUILD_DIR" ]; then
        echo "Cleaning up rpmbuild directory..."
        rm -rf "$RPMBUILD_DIR"
    fi
    if [ $exit_code -ne 0 ]; then
        echo "Build failed with exit code $exit_code" >&2
    fi
    exit $exit_code
}
trap cleanup EXIT

echo "Building SecretKeeper RPM package v${VERSION}..."

cd "$PROJECT_ROOT"

# Create directories
mkdir -p "$DIST_DIR"
mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Check for required tools
if ! command -v rpmbuild &> /dev/null; then
    echo "Error: rpmbuild not found." >&2
    echo "Install with: dnf install rpm-build (Fedora/RHEL)" >&2
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

# Build the RPM
echo "Building RPM package..."
rpmbuild -bb "$SCRIPT_DIR/rpm/secretkeeper.spec" \
    --define "_topdir $RPMBUILD_DIR" \
    --define "_sourcedir $PROJECT_ROOT" \
    --define "_builddir $PROJECT_ROOT" \
    --define "version $VERSION"

# Move generated RPMs to dist/
echo "Moving packages to dist/..."
find "$RPMBUILD_DIR/RPMS" -name "*.rpm" -exec mv {} "$DIST_DIR/" \;

# Verify package was created
RPM_COUNT=$(find "$DIST_DIR" -name "*.rpm" -type f 2>/dev/null | wc -l)
if [ "$RPM_COUNT" -eq 0 ]; then
    echo "Error: No .rpm package was created" >&2
    exit 1
fi

echo ""
echo "Package built successfully!"
echo "Output: $DIST_DIR/"
ls -la "$DIST_DIR/"*.rpm
