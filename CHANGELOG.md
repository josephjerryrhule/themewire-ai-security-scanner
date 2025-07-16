# Changelog

## [1.0.12] - 2025-07-16

### Added
- **Stop Scan Functionality**: Users can now stop running scans gracefully with proper cleanup
- **Clear Issues Feature**: Added ability to clear all issues and scan history
- **Scan-Specific Clear**: Option to clear issues from specific scans only
- **Enhanced File Validation**: Improved file scanning to only process existing files, eliminating "ghost file" errors
- **New JavaScript Module**: Added `themewire-security-additional.js` for new functionality
- **Comprehensive Documentation**: Added implementation guides and production readiness reports

### Enhanced
- **Scan Button Management**: Improved logic for showing/hiding Start, Resume, and Stop scan buttons
- **Database Operations**: Enhanced database class with new methods for clearing issues
- **AJAX Handlers**: Added new AJAX endpoints for stop scan and clear operations
- **User Interface**: Better button states and visual feedback during operations
- **Error Handling**: Improved error handling and user feedback throughout the application

### Fixed
- **JavaScript Syntax Errors**: Resolved truncated function and IIFE scope issues
- **Scan State Management**: Fixed resume button appearing after clearing all scan data
- **File Scanning Logic**: Enhanced file validation to prevent scanning non-existent files
- **Button State Logic**: Corrected scan button visibility based on actual scan status
- **Cross-File Function Access**: Resolved function accessibility between JavaScript modules

### Technical Improvements
- **File Existence Validation**: Multiple layers of file validation in scanner
- **Transient Management**: Proper cleanup of scan-related transients
- **Option Management**: Enhanced WordPress option handling for scan state
- **Code Organization**: Better separation of concerns between JavaScript modules
- **Performance**: Optimized file scanning to only process readable, existing files

### Security
- **Input Validation**: Enhanced validation for all AJAX requests
- **Capability Checks**: Proper permission checks for all administrative actions
- **Nonce Verification**: Maintained security for all new AJAX operations

### User Experience
- **Confirmation Dialogs**: Added confirmation for destructive actions
- **Progress Feedback**: Visual feedback during all operations
- **Error Messages**: Clear, actionable error messages
- **Button States**: Intuitive button management based on scan status

### Files Modified
- `admin/class-admin.php` - Enhanced with new AJAX handlers
- `admin/assets/js/themewire-security-admin.js` - Fixed syntax errors and improved structure
- `admin/assets/js/themewire-security-additional.js` - New file with stop/clear functionality
- `admin/views/scan.php` - Added stop scan and clear issues buttons
- `admin/views/issues.php` - Enhanced with clear functionality
- `includes/class-database.php` - Added clear methods
- `includes/class-scanner.php` - Enhanced with stop functionality and file validation
- `includes/class-themewire-security.php` - Registered new AJAX actions

## [1.0.11] - 2025-07-15
### Previous release
- Production readiness improvements
- Enhanced security features
- UI/UX improvements
