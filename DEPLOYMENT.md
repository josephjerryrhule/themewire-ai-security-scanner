# Themewire AI Security Scanner

## 🚀 Automated Deployment & Version Management

This plugin features a comprehensive automated deployment system using GitHub Actions for seamless version management, automated builds, and plugin updates.

### 🔄 Auto-Patch System

The plugin automatically applies patch version updates when changes are pushed to the main branch:

- **Triggers**: Push to main branch with changes to `.php`, `.js`, or `.css` files
- **Action**: Automatically increments patch version (e.g., 1.0.1 → 1.0.2)
- **Process**: Updates version numbers, commits changes, and creates production build

### 📋 Manual Release Workflow

For major and minor releases, use the manual workflow dispatch:

1. Go to **Actions** tab in GitHub repository
2. Select **"Release Management"** workflow
3. Click **"Run workflow"**
4. Choose release type:
   - **Major**: Breaking changes (1.0.0 → 2.0.0)
   - **Minor**: New features (1.0.0 → 1.1.0)
   - **Patch**: Bug fixes (1.0.0 → 1.0.1)
5. Add release notes
6. Run the workflow

### 🏗️ Production Build Process

The automated build system creates optimized production packages:

- **Clean Build**: Removes development files, logs, and unnecessary assets
- **Optimization**: Minifies code and optimizes file structure
- **Package Creation**: Creates distributable ZIP file
- **Checksums**: Generates SHA256 checksums for verification
- **Asset Management**: Only includes production-ready files

### 📦 WordPress Plugin Updater

The plugin includes a sophisticated updater that:

- **Maintains Folder Structure**: Ensures updates don't change installation directory
- **GitHub Integration**: Checks for new releases automatically
- **Smart Updates**: Handles GitHub ZIP structure automatically
- **Backup System**: Creates backups before updates
- **Update Notifications**: Shows available updates in WordPress admin

### 🛠️ Build Script Usage

You can manually create production builds:

```bash
# Make script executable
chmod +x scripts/build-production.sh

# Create production build
./scripts/build-production.sh [version]

# Example
./scripts/build-production.sh 1.2.3
```

### 📁 File Structure

```
themewire-ai-security-scanner/
├── .github/
│   └── workflows/
│       └── release.yml          # GitHub Actions workflow
├── scripts/
│   └── build-production.sh      # Production build script
├── includes/
│   └── class-github-updater.php # WordPress updater class
├── dist/                        # Generated production builds
└── themewire-ai-security-scanner.php
```

### 🔐 Security Features

- **OAuth Integration**: Supports OAuth for AI service authentication
- **API Key Management**: Secure storage and validation of API keys
- **Rate Limiting**: Built-in rate limiting for API requests
- **File Validation**: Smart comparison avoiding WordPress core files
- **Malware Detection**: AI-powered security scanning

### 🎨 UI/UX Features

- **Themewire Branding**: Consistent brand colors throughout interface
- **Responsive Design**: Mobile-friendly admin interface
- **Pagination**: Efficient handling of large datasets (50 items per page)
- **Filtering**: Advanced filtering by status and severity
- **Bulk Actions**: Perform actions on multiple items

### 🔄 Update Process

1. **Automatic Detection**: Plugin checks for updates every 12 hours
2. **Update Notification**: Shows update notice in WordPress admin
3. **One-Click Update**: Update directly from WordPress dashboard
4. **Folder Preservation**: Maintains custom folder structure
5. **Backup Creation**: Automatic backup before update
6. **Seamless Installation**: Handles GitHub ZIP structure automatically

### 📊 Version Management

- **Semantic Versioning**: Follows SemVer (Major.Minor.Patch)
- **Automatic Bumping**: GitHub Actions handle version increments
- **Git Tagging**: Creates proper Git tags for releases
- **Release Notes**: Supports detailed release documentation
- **Build Metadata**: Includes build date and Git commit info

### 🚧 Development Workflow

1. **Feature Development**: Create feature branches
2. **Pull Requests**: Submit PRs for review
3. **Merge to Main**: Triggers auto-patch if files changed
4. **Manual Releases**: Use workflow dispatch for major/minor releases
5. **Production Deployment**: Automated build and release creation

### 📈 Benefits

- **Zero Downtime**: Seamless update process
- **Consistent Releases**: Automated, error-free version management
- **Professional Distribution**: Production-optimized packages
- **User-Friendly**: Simple WordPress dashboard integration
- **Backup Safety**: Automatic backups prevent data loss
- **Version Control**: Complete audit trail of all changes

This system ensures professional-grade plugin distribution and maintenance while preserving the WordPress plugin folder structure during updates.
