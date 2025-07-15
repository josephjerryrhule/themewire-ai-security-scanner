#!/bin/bash

# Clean Script - Removes build artifacts and temporary files

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧹 Cleaning Themewire AI Security Scanner${NC}"
echo "========================================"

# Clean dist directory
if [[ -d "dist" ]]; then
    echo -e "${YELLOW}📁 Cleaning dist directory...${NC}"
    CLEANED_FILES=$(find dist -type f | wc -l)
    rm -rf dist/*
    echo -e "${GREEN}✅ Removed $CLEANED_FILES files from dist/${NC}"
else
    echo -e "${YELLOW}📁 dist directory not found${NC}"
fi

# Clean node_modules if present
if [[ -d "node_modules" ]]; then
    echo -e "${YELLOW}📦 Removing node_modules...${NC}"
    rm -rf node_modules
    echo -e "${GREEN}✅ node_modules removed${NC}"
fi

# Clean temporary files
echo -e "${YELLOW}🔍 Cleaning temporary files...${NC}"
find . -name "*.tmp" -delete 2>/dev/null
find . -name "*.log" -delete 2>/dev/null
find . -name ".DS_Store" -delete 2>/dev/null
find . -name "Thumbs.db" -delete 2>/dev/null
find . -name "*.backup" -delete 2>/dev/null

# Clean composer vendor if present
if [[ -d "vendor" ]]; then
    echo -e "${YELLOW}📚 Removing composer vendor...${NC}"
    rm -rf vendor
    echo -e "${GREEN}✅ vendor directory removed${NC}"
fi

echo -e "${GREEN}🎉 Cleanup completed!${NC}"
