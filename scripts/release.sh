#!/bin/bash
#
# Release script for skybolt (PHP adapter)
#
# Usage: ./scripts/release.sh [patch|minor|major] [--no-push]
#
# This script:
# 1. Bumps the version in VERSION file
# 2. Syncs the version to src/Skybolt.php
# 3. Commits and pushes the changes (unless --no-push is specified)
#
# The split repo's tag-version.yml workflow will automatically create the tag.

set -e

BUMP_TYPE=""
NO_PUSH=false

for arg in "$@"; do
    case "$arg" in
        --no-push)
            NO_PUSH=true
            ;;
        patch|minor|major)
            BUMP_TYPE="$arg"
            ;;
    esac
done

BUMP_TYPE=${BUMP_TYPE:-patch}

if [[ ! "$BUMP_TYPE" =~ ^(patch|minor|major)$ ]]; then
    echo "Usage: $0 [patch|minor|major] [--no-push]"
    exit 1
fi

# Get script directory and package directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PACKAGE_DIR"

# Read current version
CURRENT_VERSION=$(cat VERSION | tr -d '[:space:]')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Bump version
case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"

echo "Bumping version: ${CURRENT_VERSION} → ${NEW_VERSION}"

# Update VERSION file
echo "$NEW_VERSION" > VERSION

# Update src/Skybolt.php - VERSION constant
sed -i '' "s/VERSION = '${CURRENT_VERSION}'/VERSION = '${NEW_VERSION}'/" src/Skybolt.php

# Update src/Skybolt.php - @version tag
sed -i '' "s/@version ${CURRENT_VERSION}/@version ${NEW_VERSION}/" src/Skybolt.php

echo "Updated: VERSION, src/Skybolt.php"

# Commit and optionally push
git add -A
git commit -m "chore(php): bump skybolt to v${NEW_VERSION}"

if [ "$NO_PUSH" = true ]; then
    echo ""
    echo "✓ Committed skybolt (PHP) v${NEW_VERSION} (not pushed)"
    echo ""
    echo "Run 'git push origin main' when ready."
else
    git push origin main
    echo ""
    echo "✓ Pushed skybolt (PHP) v${NEW_VERSION}"
    echo ""
    echo "Once synced to the split repo, tag-version.yml will create the v${NEW_VERSION} tag."
fi
