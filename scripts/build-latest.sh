#!/bin/bash

# Build Latest Version Script
# Builds the current version without bumping

PLUGIN_FILE="themewire-ai-security-scanner.php"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔨 Building Latest Version${NC}"
echo "=========================="

# Get current version
CURRENT_VERSION=$(grep "Version:" "$PLUGIN_FILE" | head -1 | sed 's/.*Version: *\([0-9.]*\).*/\1/')

if [[ -z "$CURRENT_VERSION" ]]; then
    echo -e "${RED}❌ Error: Could not find version in $PLUGIN_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}📋 Current version: $CURRENT_VERSION${NC}"

# Build production package
if [[ -f "scripts/build-production.sh" ]]; then
    echo -e "${BLUE}🚀 Building production package...${NC}"
    ./scripts/build-production.sh "$CURRENT_VERSION"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Build completed successfully!${NC}"
        echo -e "${YELLOW}📦 Package: dist/themewire-ai-security-scanner-v$CURRENT_VERSION.zip${NC}"
        
        # Show package info
        if [[ -f "dist/themewire-ai-security-scanner-v$CURRENT_VERSION.zip" ]]; then
            SIZE=$(du -h "dist/themewire-ai-security-scanner-v$CURRENT_VERSION.zip" | cut -f1)
            echo -e "${BLUE}📏 Package size: $SIZE${NC}"
        fi
    else
        echo -e "${RED}❌ Error: Build failed${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Error: Build script not found${NC}"
    exit 1
fi
