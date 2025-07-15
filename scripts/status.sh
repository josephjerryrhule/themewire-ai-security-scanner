#!/bin/bash

# Status Script - Shows current project status

PLUGIN_FILE="themewire-ai-security-scanner.php"
DIST_DIR="dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}📊 Themewire AI Security Scanner - Project Status${NC}"
echo "=================================================="

# Get current version
CURRENT_VERSION=$(grep "Version:" "$PLUGIN_FILE" | head -1 | sed 's/.*Version: *\([0-9.]*\).*/\1/')
PACKAGE_VERSION=$(grep '"version"' package.json 2>/dev/null | sed 's/.*"version": *"\([0-9.]*\)".*/\1/')

echo -e "${BLUE}📋 Version Information:${NC}"
echo -e "  Plugin version: ${GREEN}$CURRENT_VERSION${NC}"
if [[ -n "$PACKAGE_VERSION" ]]; then
    if [[ "$CURRENT_VERSION" == "$PACKAGE_VERSION" ]]; then
        echo -e "  Package version: ${GREEN}$PACKAGE_VERSION${NC} ✅"
    else
        echo -e "  Package version: ${RED}$PACKAGE_VERSION${NC} ❌ (mismatch)"
    fi
fi

# Git status
echo ""
echo -e "${BLUE}📚 Git Status:${NC}"
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
echo -e "  Current branch: ${YELLOW}$CURRENT_BRANCH${NC}"

if git diff-index --quiet HEAD -- 2>/dev/null; then
    echo -e "  Working directory: ${GREEN}Clean${NC} ✅"
else
    echo -e "  Working directory: ${YELLOW}Has changes${NC} ⚠️"
    MODIFIED_COUNT=$(git status --porcelain 2>/dev/null | wc -l)
    echo -e "  Modified files: ${YELLOW}$MODIFIED_COUNT${NC}"
fi

# Check for unpushed commits
UNPUSHED=$(git log origin/"$CURRENT_BRANCH"..HEAD --oneline 2>/dev/null | wc -l)
if [[ $UNPUSHED -gt 0 ]]; then
    echo -e "  Unpushed commits: ${YELLOW}$UNPUSHED${NC} ⚠️"
else
    echo -e "  Unpushed commits: ${GREEN}0${NC} ✅"
fi

# Latest tag
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
echo -e "  Latest tag: ${YELLOW}$LATEST_TAG${NC}"

# Distribution status
echo ""
echo -e "${BLUE}📦 Distribution Status:${NC}"
if [[ -d "$DIST_DIR" ]]; then
    PACKAGE_COUNT=$(find "$DIST_DIR" -name "*.zip" | wc -l)
    echo -e "  Packages available: ${GREEN}$PACKAGE_COUNT${NC}"
    
    # Check for current version package
    CURRENT_PACKAGE="$DIST_DIR/themewire-ai-security-scanner-v$CURRENT_VERSION.zip"
    if [[ -f "$CURRENT_PACKAGE" ]]; then
        PACKAGE_SIZE=$(du -h "$CURRENT_PACKAGE" | cut -f1)
        PACKAGE_DATE=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$CURRENT_PACKAGE" 2>/dev/null || stat -c "%y" "$CURRENT_PACKAGE" 2>/dev/null | cut -d' ' -f1-2)
        echo -e "  Current version package: ${GREEN}Available${NC} ✅"
        echo -e "    Size: ${YELLOW}$PACKAGE_SIZE${NC}"
        echo -e "    Date: ${YELLOW}$PACKAGE_DATE${NC}"
        
        # Check checksum
        if [[ -f "$CURRENT_PACKAGE.sha256" ]]; then
            echo -e "    Checksum: ${GREEN}Available${NC} ✅"
        else
            echo -e "    Checksum: ${RED}Missing${NC} ❌"
        fi
    else
        echo -e "  Current version package: ${RED}Not built${NC} ❌"
        echo -e "    ${YELLOW}💡 Run 'npm run build:latest' to create package${NC}"
    fi
    
    # List all packages
    if [[ $PACKAGE_COUNT -gt 0 ]]; then
        echo -e "  Available packages:"
        find "$DIST_DIR" -name "*.zip" -exec basename {} \; | sort -V | while read package; do
            echo -e "    - ${YELLOW}$package${NC}"
        done
    fi
else
    echo -e "  Distribution directory: ${RED}Not found${NC} ❌"
fi

# GitHub CLI status
echo ""
echo -e "${BLUE}🔧 Tools Status:${NC}"
if command -v gh &> /dev/null; then
    echo -e "  GitHub CLI: ${GREEN}Available${NC} ✅"
    GH_AUTH_STATUS=$(gh auth status 2>&1 | grep -q "Logged in" && echo "Authenticated" || echo "Not authenticated")
    echo -e "  GitHub Auth: ${YELLOW}$GH_AUTH_STATUS${NC}"
else
    echo -e "  GitHub CLI: ${RED}Not installed${NC} ❌"
    echo -e "    ${YELLOW}💡 Install with: brew install gh${NC}"
fi

if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "  Node.js: ${GREEN}$NODE_VERSION${NC} ✅"
else
    echo -e "  Node.js: ${RED}Not installed${NC} ❌"
fi

if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    echo -e "  npm: ${GREEN}v$NPM_VERSION${NC} ✅"
else
    echo -e "  npm: ${RED}Not installed${NC} ❌"
fi

# Quick actions
echo ""
echo -e "${BLUE}🚀 Quick Actions:${NC}"
echo -e "  ${YELLOW}npm run version:patch${NC}  - Bump patch version and build"
echo -e "  ${YELLOW}npm run build:latest${NC}   - Build current version"
echo -e "  ${YELLOW}npm run release${NC}        - Create GitHub release"
echo -e "  ${YELLOW}npm run clean${NC}          - Clean build artifacts"
echo -e "  ${YELLOW}npm run help${NC}           - Show all available commands"
