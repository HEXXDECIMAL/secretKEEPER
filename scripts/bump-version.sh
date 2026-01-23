#!/bin/bash
set -e

TYPE=${1:-patch}
CURRENT=$(cat VERSION 2>/dev/null || echo "0.0.0")

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
case $TYPE in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
    *) echo "Usage: $0 [major|minor|patch]"; exit 1 ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"
echo "$NEW_VERSION" > VERSION

# Update Cargo.toml workspace version
sed -i '' "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml

echo "Bumped version: $CURRENT -> $NEW_VERSION"
