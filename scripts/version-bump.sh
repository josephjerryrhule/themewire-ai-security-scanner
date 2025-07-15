#!/bin/bash

# Version Bump Script for Themewire AI Security Scanner
# Usage: ./version-bump.sh [patch|minor|major]

VERSION_TYPE=${1:-"patch"}
PLUGIN_FILE="themewire-ai-security-scanner.php"
PACKAGE_FILE="package.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔢 Themewire AI Security Scanner - Version Bump${NC}"
echo "=================================================="

# Validate version type
if [[ ! "$VERSION_TYPE" =~ ^(patch|minor|major)$ ]]; then
    echo -e "${RED}❌ Error: Invalid version type '$VERSION_TYPE'${NC}"
    echo "Usage: $0 [patch|minor|major]"
    exit 1
fi

# Check if required files exist
if [[ ! -f "$PLUGIN_FILE" ]]; then
    echo -e "${RED}❌ Error: Plugin file '$PLUGIN_FILE' not found${NC}"
    exit 1
fi

# Get current version from plugin file
CURRENT_VERSION=$(grep "Version:" "$PLUGIN_FILE" | head -1 | sed 's/.*Version: *\([0-9.]*\).*/\1/')

if [[ -z "$CURRENT_VERSION" ]]; then
    echo -e "${RED}❌ Error: Could not find version in $PLUGIN_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}📋 Current version: $CURRENT_VERSION${NC}"

# Parse version components
IFS='.' read -r major minor patch_num <<< "$CURRENT_VERSION"

# Validate version format
if [[ ! "$major" =~ ^[0-9]+$ ]] || [[ ! "$minor" =~ ^[0-9]+$ ]] || [[ ! "$patch_num" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}❌ Error: Invalid version format '$CURRENT_VERSION'. Expected format: X.Y.Z${NC}"
    exit 1
fi

# Calculate new version
case "$VERSION_TYPE" in
    "major")
        NEW_MAJOR=$((major + 1))
        NEW_VERSION="$NEW_MAJOR.0.0"
        ;;
    "minor")
        NEW_MINOR=$((minor + 1))
        NEW_VERSION="$major.$NEW_MINOR.0"
        ;;
    "patch")
        NEW_PATCH=$((patch_num + 1))
        NEW_VERSION="$major.$minor.$NEW_PATCH"
        ;;
esac

echo -e "${GREEN}🚀 Bumping $VERSION_TYPE version: $CURRENT_VERSION → $NEW_VERSION${NC}"

# Update plugin file
echo -e "${BLUE}📝 Updating $PLUGIN_FILE...${NC}"
sed -i.backup "s/\* Version: [0-9.]*/* Version: $NEW_VERSION/" "$PLUGIN_FILE"
sed -i.backup "s/define('TWSS_VERSION', '[0-9.]*');/define('TWSS_VERSION', '$NEW_VERSION');/" "$PLUGIN_FILE"

# Update package.json if it exists
if [[ -f "$PACKAGE_FILE" ]]; then
    echo -e "${BLUE}📝 Updating $PACKAGE_FILE...${NC}"
    sed -i.backup "s/\"version\": \"[0-9.]*\"/\"version\": \"$NEW_VERSION\"/" "$PACKAGE_FILE"
fi

# Remove backup files
rm -f "$PLUGIN_FILE.backup" "$PACKAGE_FILE.backup" 2>/dev/null

# Verify the changes
NEW_PLUGIN_VERSION=$(grep "Version:" "$PLUGIN_FILE" | head -1 | sed 's/.*Version: *\([0-9.]*\).*/\1/')
if [[ "$NEW_PLUGIN_VERSION" == "$NEW_VERSION" ]]; then
    echo -e "${GREEN}✅ Version successfully updated to $NEW_VERSION${NC}"
else
    echo -e "${RED}❌ Error: Version update failed. Expected $NEW_VERSION, got $NEW_PLUGIN_VERSION${NC}"
    exit 1
fi

# Auto-build after version bump
echo -e "${BLUE}🔨 Building distribution package...${NC}"
if [[ -f "scripts/build-production.sh" ]]; then
    ./scripts/build-production.sh "$NEW_VERSION"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Distribution package created successfully!${NC}"
        echo -e "${YELLOW}📦 Package: dist/themewire-ai-security-scanner-v$NEW_VERSION.zip${NC}"
    else
        echo -e "${RED}❌ Error: Distribution build failed${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  Warning: Build script not found. Skipping distribution build.${NC}"
fi

# Git operations
echo -e "${BLUE}📚 Git operations...${NC}"
git add "$PLUGIN_FILE" "$PACKAGE_FILE"
git commit -m "$VERSION_TYPE: bump version to $NEW_VERSION

- Updated plugin version from $CURRENT_VERSION to $NEW_VERSION
- Generated production build package
- Ready for release"

# Push to GitHub
echo -e "${BLUE}🚀 Pushing to GitHub...${NC}"

# First, try to pull any remote changes
echo -e "${YELLOW}📥 Pulling latest changes...${NC}"
if git pull --rebase themewire main; then
    echo -e "${GREEN}✅ Successfully pulled latest changes${NC}"
else
    echo -e "${YELLOW}⚠️  No remote changes to pull${NC}"
fi

# Now try to push
if git push themewire main; then
    echo -e "${GREEN}✅ Successfully pushed to GitHub${NC}"
else
    echo -e "${RED}❌ Failed to push to GitHub${NC}"
    echo -e "${YELLOW}💡 You may need to resolve conflicts and push manually: git push${NC}"
fi

echo -e "${GREEN}🎉 Version bump completed!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  ${YELLOW}1.${NC} Review changes: git show HEAD"
echo -e "  ${YELLOW}2.${NC} Create release: npm run release"
echo -e "  ${YELLOW}3.${NC} GitHub Actions will auto-trigger on push"
echo ""
