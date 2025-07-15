#!/bin/bash

# Help Script - Shows available commands and usage

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}📚 Themewire AI Security Scanner - Help${NC}"
echo "========================================"
echo ""

echo -e "${BOLD}${BLUE}🔢 Version Management:${NC}"
echo -e "  ${GREEN}npm run version:patch${NC}     Bump patch version (1.0.1 → 1.0.2)"
echo -e "  ${GREEN}npm run version:minor${NC}     Bump minor version (1.0.1 → 1.1.0)"
echo -e "  ${GREEN}npm run version:major${NC}     Bump major version (1.0.1 → 2.0.0)"
echo ""

echo -e "${BOLD}${BLUE}🔨 Building:${NC}"
echo -e "  ${GREEN}npm run build${NC}             Build with version argument"
echo -e "  ${GREEN}npm run build:latest${NC}      Build current version package"
echo ""

echo -e "${BOLD}${BLUE}🚀 Releasing:${NC}"
echo -e "  ${GREEN}npm run release${NC}           Create production GitHub release"
echo -e "  ${GREEN}npm run release:draft${NC}     Create draft release"
echo -e "  ${GREEN}npm run release:prerelease${NC} Create pre-release"
echo ""

echo -e "${BOLD}${BLUE}🧹 Maintenance:${NC}"
echo -e "  ${GREEN}npm run clean${NC}             Clean build artifacts and temp files"
echo -e "  ${GREEN}npm run status${NC}            Show project status and information"
echo -e "  ${GREEN}npm run help${NC}              Show this help message"
echo ""

echo -e "${BOLD}${BLUE}📋 Typical Workflow:${NC}"
echo -e "${YELLOW}1.${NC} Development and testing"
echo -e "${YELLOW}2.${NC} ${GREEN}npm run version:patch${NC}     (or minor/major)"
echo -e "${YELLOW}3.${NC} ${GREEN}git push${NC}                  (push version bump)"
echo -e "${YELLOW}4.${NC} ${GREEN}npm run release${NC}           (create GitHub release)"
echo ""

echo -e "${BOLD}${BLUE}🔧 Direct Script Usage:${NC}"
echo -e "  ${YELLOW}./scripts/version-bump.sh patch${NC}"
echo -e "  ${YELLOW}./scripts/build-production.sh 1.0.5${NC}"
echo -e "  ${YELLOW}./scripts/release.sh --draft${NC}"
echo ""

echo -e "${BOLD}${BLUE}📁 File Structure:${NC}"
echo -e "  ${YELLOW}scripts/${NC}               Build and release scripts"
echo -e "  ${YELLOW}dist/${NC}                  Production packages"
echo -e "  ${YELLOW}package.json${NC}           npm scripts configuration"
echo ""

echo -e "${BOLD}${BLUE}🎯 Examples:${NC}"
echo ""
echo -e "${YELLOW}# Quick patch release:${NC}"
echo -e "${GREEN}npm run version:patch && git push && npm run release${NC}"
echo ""
echo -e "${YELLOW}# Build without version bump:${NC}"
echo -e "${GREEN}npm run build:latest${NC}"
echo ""
echo -e "${YELLOW}# Create draft release:${NC}"
echo -e "${GREEN}npm run release:draft${NC}"
echo ""
echo -e "${YELLOW}# Check project status:${NC}"
echo -e "${GREEN}npm run status${NC}"
echo ""

echo -e "${BOLD}${BLUE}⚙️  Requirements:${NC}"
echo -e "  • ${YELLOW}Node.js${NC} and ${YELLOW}npm${NC} for script execution"
echo -e "  • ${YELLOW}GitHub CLI${NC} (optional) for automatic releases"
echo -e "  • ${YELLOW}Git${NC} configured with proper authentication"
echo ""

echo -e "${BOLD}${BLUE}🔗 Links:${NC}"
echo -e "  Repository: ${YELLOW}https://github.com/josephjerryrhule/themewire-ai-security-scanner${NC}"
echo -e "  Releases: ${YELLOW}https://github.com/josephjerryrhule/themewire-ai-security-scanner/releases${NC}"
