#!/bin/bash

# ThemeWire AI Security Scanner - Production Build Script
# Usage: ./scripts/build-production.sh [version]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get version from command line argument or default
VERSION=${1:-"1.0.42"}
PLUGIN_NAME="themewire-ai-security-scanner"
BUILD_DIR="build"
DIST_DIR="dist"

print_status "Starting production build for ${PLUGIN_NAME} v${VERSION}"

# Validate we're in the correct directory
if [[ ! -f "themewire-ai-security-scanner.php" ]]; then
    print_error "Error: Main plugin file not found. Are you in the plugin root directory?"
    exit 1
fi

# Clean previous builds
print_status "Cleaning previous builds..."
rm -rf "${BUILD_DIR}" "${DIST_DIR}"
mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

# Update version in main plugin file
print_status "Updating version to ${VERSION}..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/Version: [0-9]\+\.[0-9]\+\.[0-9]\+/Version: ${VERSION}/" themewire-ai-security-scanner.php
    sed -i '' "s/define('THEMEWIRE_SECURITY_VERSION', '[^']*')/define('THEMEWIRE_SECURITY_VERSION', '${VERSION}')/" themewire-ai-security-scanner.php
    sed -i '' "s/define('TWSS_VERSION', '[^']*')/define('TWSS_VERSION', '${VERSION}')/" themewire-ai-security-scanner.php
else
    # Linux
    sed -i "s/Version: [0-9]\+\.[0-9]\+\.[0-9]\+/Version: ${VERSION}/" themewire-ai-security-scanner.php
    sed -i "s/define('THEMEWIRE_SECURITY_VERSION', '[^']*')/define('THEMEWIRE_SECURITY_VERSION', '${VERSION}')/" themewire-ai-security-scanner.php
    sed -i "s/define('TWSS_VERSION', '[^']*')/define('TWSS_VERSION', '${VERSION}')/" themewire-ai-security-scanner.php
fi

# Copy essential files to build directory
print_status "Copying production files..."
cp -r . "${BUILD_DIR}/${PLUGIN_NAME}/"

# Navigate to build directory
cd "${BUILD_DIR}/${PLUGIN_NAME}"

# Remove development and test files
print_status "Removing development files..."
rm -rf \
    .git \
    .gitignore \
    .github \
    node_modules \
    package*.json \
    composer.json \
    composer.lock \
    phpunit.xml \
    tests/ \
    test-*.php \
    debug-*.php \
    emergency-*.php \
    enhanced-*.php \
    simple-*.php \
    standalone-*.php \
    verify-*.sh \
    fix_*.py \
    *.md \
    scripts/ \
    build/ \
    dist/ \
    .vscode/ \
    .idea/ \
    *.log \
    .DS_Store \
    Thumbs.db

# Remove any backup files
find . -name "*.bak" -delete
find . -name "*~" -delete
find . -name "*.orig" -delete

# Navigate back to project root
cd ../..

# Create ZIP archive
print_status "Creating production ZIP archive..."
cd "${BUILD_DIR}"
zip -r "../${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" "${PLUGIN_NAME}/" -x "*.DS_Store" "*/.*"
cd ..

# Generate checksums
print_status "Generating checksums..."
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" > "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip.sha256"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" > "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip.sha256"
else
    print_warning "No SHA256 utility found, skipping checksum generation"
fi

# Get file size
FILE_SIZE=$(ls -lh "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" | awk '{print $5}')

# Display build summary
echo
print_success "Production build completed successfully!"
echo
echo "Build Details:"
echo "  Plugin: ${PLUGIN_NAME}"
echo "  Version: ${VERSION}"
echo "  Archive: ${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip"
echo "  Size: ${FILE_SIZE}"
echo

# Validate the build
print_status "Validating build..."
if [[ -f "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" ]]; then
    print_success "Build validation passed"
    
    # Show contents
    echo
    print_status "Package contents:"
    unzip -l "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" | head -20
    echo
    
    # Show file count
    FILE_COUNT=$(unzip -l "${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip" | tail -1 | awk '{print $2}')
    echo "Total files: ${FILE_COUNT}"
else
    print_error "Build validation failed - ZIP file not found"
    exit 1
fi

print_success "Production build ready for deployment: ${DIST_DIR}/${PLUGIN_NAME}-${VERSION}.zip"
