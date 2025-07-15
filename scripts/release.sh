#!/bin/bash

# Release Script for Themewire AI Security Scanner
# Creates GitHub releases from dist packages

PLUGIN_FILE="themewire-ai-security-scanner.php"
DIST_DIR="dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
DRAFT_MODE=false
PRERELEASE_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --draft)
            DRAFT_MODE=true
            shift
            ;;
        --prerelease)
            PRERELEASE_MODE=true
            shift
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            echo "Usage: $0 [--draft] [--prerelease]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}🚀 Themewire AI Security Scanner - Release Manager${NC}"
echo "================================================="

# Get current version
CURRENT_VERSION=$(grep "Version:" "$PLUGIN_FILE" | head -1 | sed 's/.*Version: *\([0-9.]*\).*/\1/')

if [[ -z "$CURRENT_VERSION" ]]; then
    echo -e "${RED}❌ Error: Could not find version in $PLUGIN_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}📋 Current version: $CURRENT_VERSION${NC}"

# Check if dist package exists
PACKAGE_FILE="$DIST_DIR/themewire-ai-security-scanner-v$CURRENT_VERSION.zip"
CHECKSUM_FILE="$PACKAGE_FILE.sha256"

if [[ ! -f "$PACKAGE_FILE" ]]; then
    echo -e "${RED}❌ Error: Distribution package not found: $PACKAGE_FILE${NC}"
    echo -e "${YELLOW}💡 Tip: Run 'npm run build:latest' to create the package${NC}"
    exit 1
fi

if [[ ! -f "$CHECKSUM_FILE" ]]; then
    echo -e "${YELLOW}⚠️  Warning: Checksum file not found. Creating one...${NC}"
    if command -v sha256sum &> /dev/null; then
        sha256sum "$PACKAGE_FILE" > "$CHECKSUM_FILE"
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$PACKAGE_FILE" > "$CHECKSUM_FILE"
    fi
fi

# Get package info
PACKAGE_SIZE=$(du -h "$PACKAGE_FILE" | cut -f1)
CHECKSUM=$(cat "$CHECKSUM_FILE" | cut -d' ' -f1)

echo -e "${BLUE}📦 Package details:${NC}"
echo -e "  File: $PACKAGE_FILE"
echo -e "  Size: $PACKAGE_SIZE"
echo -e "  SHA256: $CHECKSUM"

# Determine release type
RELEASE_TYPE="Release"
if [[ "$DRAFT_MODE" == true ]]; then
    RELEASE_TYPE="Draft Release"
elif [[ "$PRERELEASE_MODE" == true ]]; then
    RELEASE_TYPE="Pre-release"
fi

echo -e "${YELLOW}🏷️  Creating $RELEASE_TYPE v$CURRENT_VERSION...${NC}"

# Check git status
if ! git diff-index --quiet HEAD --; then
    echo -e "${YELLOW}⚠️  Warning: You have uncommitted changes${NC}"
    echo -e "${BLUE}Uncommitted files:${NC}"
    git status --porcelain
    echo ""
    read -p "Continue with release? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}📋 Release cancelled${NC}"
        exit 0
    fi
fi

# Check if tag already exists
if git tag | grep -q "^v$CURRENT_VERSION$"; then
    echo -e "${YELLOW}⚠️  Tag v$CURRENT_VERSION already exists${NC}"
    read -p "Continue anyway? This will update the existing release. (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}📋 Release cancelled${NC}"
        exit 0
    fi
else
    # Create and push tag
    echo -e "${BLUE}🏷️  Creating git tag v$CURRENT_VERSION...${NC}"
    git tag -a "v$CURRENT_VERSION" -m "Release v$CURRENT_VERSION"
    git push origin "v$CURRENT_VERSION"
fi

# Generate release notes
RELEASE_NOTES="## Themewire AI Security Scanner v$CURRENT_VERSION

### 📦 Package Information
- **Version**: $CURRENT_VERSION
- **Package Size**: $PACKAGE_SIZE
- **SHA256 Checksum**: \`$CHECKSUM\`

### 🔗 Installation
1. Download \`themewire-ai-security-scanner-v$CURRENT_VERSION.zip\`
2. Upload through WordPress Admin → Plugins → Add New → Upload Plugin
3. Activate the plugin

### 🛡️ Features
- AI-powered security scanning
- Malware detection and quarantine
- Real-time vulnerability monitoring
- Automated security fixes
- Comprehensive security dashboard

### 📋 Requirements
- **WordPress**: 5.6 or higher
- **PHP**: 7.4 or higher

### 🔐 Verification
To verify the package integrity:
\`\`\`bash
sha256sum themewire-ai-security-scanner-v$CURRENT_VERSION.zip
# Should match: $CHECKSUM
\`\`\`"

# Use GitHub CLI if available
if command -v gh &> /dev/null; then
    echo -e "${BLUE}📤 Creating GitHub release using GitHub CLI...${NC}"
    
    RELEASE_CMD="gh release create v$CURRENT_VERSION \"$PACKAGE_FILE\" \"$CHECKSUM_FILE\" --title \"Release v$CURRENT_VERSION\" --notes \"$RELEASE_NOTES\""
    
    if [[ "$DRAFT_MODE" == true ]]; then
        RELEASE_CMD="$RELEASE_CMD --draft"
    fi
    
    if [[ "$PRERELEASE_MODE" == true ]]; then
        RELEASE_CMD="$RELEASE_CMD --prerelease"
    fi
    
    eval $RELEASE_CMD
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ GitHub release created successfully!${NC}"
        echo -e "${BLUE}🔗 View release: https://github.com/josephjerryrhule/themewire-ai-security-scanner/releases/tag/v$CURRENT_VERSION${NC}"
    else
        echo -e "${RED}❌ Error: Failed to create GitHub release${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  GitHub CLI not found. Using manual release instructions...${NC}"
    echo ""
    echo -e "${BLUE}📋 Manual Release Instructions:${NC}"
    echo "1. Go to: https://github.com/josephjerryrhule/themewire-ai-security-scanner/releases/new"
    echo "2. Tag version: v$CURRENT_VERSION"
    echo "3. Release title: Release v$CURRENT_VERSION"
    echo "4. Upload files:"
    echo "   - $PACKAGE_FILE"
    echo "   - $CHECKSUM_FILE"
    echo "5. Copy and paste the release notes below:"
    echo ""
    echo "=== RELEASE NOTES ==="
    echo "$RELEASE_NOTES"
    echo "===================="
fi

echo ""
echo -e "${GREEN}🎉 Release process completed!${NC}"
echo -e "${BLUE}📦 Released version: $CURRENT_VERSION${NC}"
echo -e "${BLUE}📁 Package: $PACKAGE_FILE${NC}"
