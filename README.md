# Themewire AI Security Scanner

AI-powered WordPress security scanner that detects, fixes, and quarantines malware and security vulnerabilities.

## Features

🔍 **AI-Powered Detection**: Advanced machine learning algorithms to identify security threats  
🛡️ **Real-time Protection**: Continuous monitoring of your WordPress site  
🔧 **Automatic Fixes**: Intelligent remediation of common vulnerabilities  
📊 **Detailed Reports**: Comprehensive security analysis and recommendations  
⚡ **Performance Optimized**: Minimal impact on site performance  
🔄 **Auto-Updates**: Automatic plugin updates with GitHub integration  

## Installation

### From WordPress Admin
1. Download the latest release ZIP from [GitHub Releases](https://github.com/josephjerryrhule/themewire-ai-security-scanner/releases)
2. Go to **Plugins → Add New → Upload Plugin**
3. Upload the ZIP file and activate

### From Source
```bash
git clone https://github.com/josephjerryrhule/themewire-ai-security-scanner.git
cd themewire-ai-security-scanner
npm install
npm run build
```

## Development

### Prerequisites
- Node.js 14+ 
- PHP 7.4+
- WordPress 5.6+

### NPM Scripts

```bash
# Version Management
npm run version:patch    # Bump patch version (1.0.0 → 1.0.1)
npm run version:minor    # Bump minor version (1.0.0 → 1.1.0)  
npm run version:major    # Bump major version (1.0.0 → 2.0.0)

# Building
npm run build           # Build production package with current version
npm run build:latest    # Build latest version without bumping

# Release Management
npm run release         # Create GitHub release with latest build
npm run release:draft   # Create draft release
npm run release:prerelease # Create pre-release

# Utilities
npm run clean          # Clean build artifacts
npm run status         # Show current version and build status
npm run help           # Show available commands
```

### Workflow

1. **Make changes** to your code
2. **Bump version**: `npm run version:patch`
3. **Build package**: `npm run build`
4. **Create release**: `npm run release`

### GitHub Actions

The repository includes automated workflows for:
- **Auto-patch**: Automatically bumps patch version on push to main
- **Manual release**: Create releases with custom version bumps
- **Production builds**: Generates optimized plugin packages

## File Structure

```
themewire-ai-security-scanner/
├── themewire-ai-security-scanner.php  # Main plugin file
├── includes/                          # Core classes
│   ├── class-themewire-security.php
│   ├── class-scanner.php
│   ├── class-ai-analyzer.php
│   └── ...
├── admin/                             # Admin interface
│   ├── class-admin.php
│   ├── assets/
│   └── views/
├── scripts/                           # Build & release scripts
├── .github/workflows/                 # GitHub Actions
└── dist/                             # Production builds (gitignored)
```

## Requirements

- **PHP**: 7.4 or higher
- **WordPress**: 5.6 or higher
- **Memory**: 128MB minimum (256MB recommended)

## Security

This plugin handles sensitive security data. Please:
- Keep the plugin updated
- Review security logs regularly
- Report vulnerabilities to [security@themewire.co](mailto:security@themewire.co)

## Support

- **Documentation**: [GitHub Wiki](https://github.com/josephjerryrhule/themewire-ai-security-scanner/wiki)
- **Issues**: [GitHub Issues](https://github.com/josephjerryrhule/themewire-ai-security-scanner/issues)
- **Email**: [support@themewire.co](mailto:support@themewire.co)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## License

This plugin is licensed under the [GPL-2.0+](LICENSE) license.

## Credits

Developed by [Themewire LTD](https://themewire.co) with ❤️ for the WordPress community.

---

**⚠️ Important**: This plugin requires an active API key for AI features. Get yours at [Themewire Dashboard](https://dashboard.themewire.co).
