#!/bin/bash

# Production Build Script for Themewire AI Security Scanner
# Usage: ./build-production.sh [version]

VERSION=${1:-"1.0.0"}
PLUGIN_NAME="themewire-ai-security-scanner"
BUILD_DIR="dist"
TEMP_DIR="$BUILD_DIR/temp"
FINAL_ZIP="$BUILD_DIR/${PLUGIN_NAME}-v${VERSION}.zip"

echo "🚀 Building Themewire AI Security Scanner v${VERSION} for production..."

# Clean previous builds
rm -rf "$BUILD_DIR"
mkdir -p "$TEMP_DIR/$PLUGIN_NAME"

echo "📁 Copying necessary files..."

# Copy core plugin files to the plugin directory
cp themewire-ai-security-scanner.php "$TEMP_DIR/$PLUGIN_NAME/"
cp wp-config.php "$TEMP_DIR/$PLUGIN_NAME/" 2>/dev/null || echo "No wp-config.php found (optional)"
cp README.md "$TEMP_DIR/$PLUGIN_NAME/" 2>/dev/null || echo "No README.md found (optional)"
cp LICENSE "$TEMP_DIR/$PLUGIN_NAME/" 2>/dev/null || echo "No LICENSE file found (optional)"

# Copy admin directory (preserve structure)
if [ -d "admin" ]; then
    cp -r admin "$TEMP_DIR/$PLUGIN_NAME/"
fi

# Copy includes directory (preserve structure - this is critical for WordPress)
if [ -d "includes" ]; then
    cp -r includes "$TEMP_DIR/$PLUGIN_NAME/"
fi

# Optimize assets (but don't run npm build to avoid loops)
echo "🎨 Optimizing assets..."

# Install production dependencies if package.json exists (but don't run build)
if command -v npx &> /dev/null && [ -f package.json ]; then
    echo "📦 Installing production dependencies..."
    npm install --production --silent
    # Note: Removed npm run build to prevent circular dependency
fi

# Remove development files from admin assets
find "$TEMP_DIR/$PLUGIN_NAME/admin/assets" -name "*.map" -delete 2>/dev/null
find "$TEMP_DIR/$PLUGIN_NAME/admin/assets" -name "*.scss" -delete 2>/dev/null
find "$TEMP_DIR/$PLUGIN_NAME/admin/assets" -name "*.less" -delete 2>/dev/null

# Remove development and sensitive files
echo "🧹 Cleaning development files..."
find "$TEMP_DIR" -name ".git*" -exec rm -rf {} + 2>/dev/null
find "$TEMP_DIR" -name "node_modules" -exec rm -rf {} + 2>/dev/null
find "$TEMP_DIR" -name ".DS_Store" -delete 2>/dev/null
find "$TEMP_DIR" -name "Thumbs.db" -delete 2>/dev/null
find "$TEMP_DIR" -name "*.tmp" -delete 2>/dev/null
find "$TEMP_DIR" -name "*.log" -delete 2>/dev/null
find "$TEMP_DIR" -name ".env*" -delete 2>/dev/null
find "$TEMP_DIR" -name "composer.lock" -delete 2>/dev/null
find "$TEMP_DIR" -name "package-lock.json" -delete 2>/dev/null
find "$TEMP_DIR" -name "yarn.lock" -delete 2>/dev/null

# Remove development scripts and configs
rm -f "$TEMP_DIR/$PLUGIN_NAME/package.json"
rm -f "$TEMP_DIR/$PLUGIN_NAME/composer.json"
rm -f "$TEMP_DIR/$PLUGIN_NAME/webpack.config.js"
rm -f "$TEMP_DIR/$PLUGIN_NAME/gulpfile.js"
rm -rf "$TEMP_DIR/$PLUGIN_NAME/tests/"
rm -rf "$TEMP_DIR/$PLUGIN_NAME/scripts/"
rm -rf "$TEMP_DIR/$PLUGIN_NAME/.github/"

# Optimize PHP files (light optimization - preserve functionality)
echo "⚡ Optimizing PHP files..."
# Note: Aggressive comment/whitespace removal disabled to preserve functionality
# Only remove obvious development comments but keep plugin headers and essential comments

# Create version info file
echo "📋 Creating version info..."
cat > "$TEMP_DIR/$PLUGIN_NAME/version-info.json" << EOF
{
    "version": "$VERSION",
    "build_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "build_type": "production",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git branch --show-current 2>/dev/null || echo 'unknown')"
}
EOF

# Create production zip
echo "📦 Creating production package..."
cd "$TEMP_DIR"
zip -r "../$(basename "$FINAL_ZIP")" "$PLUGIN_NAME/" -q

# Clean up temp directory
cd - > /dev/null
rm -rf "$TEMP_DIR"

# Verify the build
if [ -f "$FINAL_ZIP" ]; then
    SIZE=$(du -h "$FINAL_ZIP" | cut -f1)
    echo "✅ Production build completed successfully!"
    echo "📦 Package: $FINAL_ZIP"
    echo "📏 Size: $SIZE"
    echo "🔍 Contents:"
    unzip -l "$FINAL_ZIP" | grep -E "(files|File)" | tail -1
else
    echo "❌ Build failed!"
    exit 1
fi

# Create checksums
echo "🔐 Creating checksums..."
if command -v sha256sum &> /dev/null; then
    sha256sum "$FINAL_ZIP" > "$FINAL_ZIP.sha256"
elif command -v shasum &> /dev/null; then
    shasum -a 256 "$FINAL_ZIP" > "$FINAL_ZIP.sha256"
fi

# Clean up temporary files
echo "🧹 Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo "🎉 Build process completed for v${VERSION}!"
