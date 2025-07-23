# Changelog

## [1.0.47] - 2025-07-23

### Fixed
- **Critical Scan Completion Issue**: Completely resolved issue where scans showed "0 scanned files" despite successful completion
  - Fixed dashboard stale scan detection logic that was prematurely marking scans as completed when users switched pages
  - Changed stale scan timeout from instant to 15-minute reasonable threshold
  - Added proper file count calculation when dashboard marks scans as completed
  - Enhanced scanner with fresh inventory recalculation fallback to ensure accurate file counts
  - Implemented multi-layer completion logic: scan_state → fresh inventory → database stats → files_scanned
  - Added database-level protection against saving 0 file counts with fallback validation
  - Scans now consistently show correct file counts (7,434+ files) and complete naturally in ~35 seconds

### Enhanced
- **Production Build System**: Fixed and improved production build process
  - Fixed circular copy issue in build script using rsync with proper exclusions
  - Build script now properly excludes build/, dist/, and .git directories during copy
  - Generated clean production ZIP package (125K) with 32 essential files
  - Added SHA256 checksum generation for build verification
  - Removed all build artifacts from git tracking following best practices

### Cleaned
- **Debug Code Removal**: Removed all debug infrastructure for production readiness
  - Eliminated extensive CRITICAL DEBUG logging from scanner class
  - Removed debug file creation code and verbose error_log statements
  - Cleaned up debug files: debug-*.php, test-*.php, db-test.php, debug-capture.php
  - Preserved all functional fixes while removing only debug/logging code
  - Added build/ directory to .gitignore to prevent future build artifact commits

### Technical
- **Database Connectivity**: Enhanced database operations with comprehensive validation
- **Error Handling**: Improved error handling and logging throughout scanner system
- **Code Quality**: Production-ready codebase with all debug infrastructure removed
- **Version Control**: Proper gitignore configuration and clean repository structure

## [1.0.21] - 2025-07-22

### Added
- **Manual Ghost File Cleanup**: Added "Clean Ghost Files" button to scan page for manual cleanup of non-existent files
  - New AJAX endpoint `twss_cleanup_ghost_files` for manual ghost file cleanup
  - Enhanced cleanup method to specifically check for non-existent themes and plugins
  - Button appears in scan page alongside other cleanup options
  - Provides user feedback showing count of ghost files removed

### Enhanced
- **Comprehensive Ghost File Detection**: Improved ghost file detection to catch theme and plugin directory issues
  - Checks for theme files referencing non-existent theme directories
  - Validates plugin files against actual plugin directory existence  
  - Prevents scan results from showing files for uninstalled themes/plugins like twentytwentyfour, twentytwentyfive, akismet
  - More thorough validation prevents ghost entries from persisting in database

### Fixed
- **Ghost File Persistence**: Addresses issue where scan results show files from themes/plugins that don't exist on WordPress instance
  - Enhanced database cleanup specifically targets theme and plugin ghost files
  - Manual cleanup option allows users to immediately remove ghost files from existing scan results

## [1.0.20] - 2025-07-22

### Fixed
- **JavaScript Error**: Fixed "Uncaught ReferenceError: performIssueAction is not defined" error
  - Added missing `performIssueAction()` function to handle issue actions (fix, quarantine, whitelist, delete, restore)
  - Function includes proper error handling, loading states, and user feedback
  - Supports various issue actions with customizable loading text and extra data parameters
  - Integrates with existing AJAX endpoints for issue management
  - Provides smooth UI updates by removing completed issue rows from the table

## [1.0.19] - 2025-07-22

### Fixed
- **Ghost File Prevention**: Enhanced database-level validation to prevent ghost files from appearing in scan results
  - Added comprehensive 8-layer file validation in `add_issue()` method
  - Validates file existence, file type, readability, realpath resolution, and file size
  - Added `cleanup_ghost_issues()` method to remove existing ghost files from database
  - Automatic cleanup runs before each new scan to ensure data integrity
  - Special handling for legitimate missing file issue types (core_file_missing, plugin_file_missing, theme_file_missing)
  - Enhanced error logging for skipped ghost files during database operations

### Improved  
- **Data Integrity**: Scan results now only show files that actually exist on the WordPress instance
- **Database Operations**: More robust file validation prevents invalid entries in issues table

## [1.0.18] - 2025-07-22

### Fixed
- **Scan Progress Timeout**: Fixed scan progress not updating, causing apparent timeouts
  - Added missing `pollScanStatus()` function to continuously poll scan progress
  - Enhanced `get_scan_summary()` to return current stage and progress information
  - Progress now updates every 2 seconds showing real-time scan status
  - Prevents scan timeout appearance by providing visual feedback during long scans

## [1.0.17] - 2025-07-22

### Fixed
- **Database Method Error**: Fixed fatal error "Call to undefined method update_scan_counts()" 
  - Added missing `update_scan_counts()` method to database class
  - Method properly updates issues_found and issues_fixed counts in scans table
  - Resolves error when clearing scan issues from admin interface

## [1.0.16] - 2025-07-22

### Fixed
- **JavaScript Error**: Fixed "Uncaught ReferenceError: performAIAnalysis is not defined" error
  - Added missing `performAIAnalysis()` function to handle AI analysis of individual security issues
  - Function includes proper error handling, loading states, and user feedback
  - Integrates with existing `twss_analyze_issue` AJAX endpoint

## [1.0.15] - 2025-07-22

### Fixed
- **Version Page Error**: Fixed fatal error in version page when checking for updates
  - Corrected GitHub updater constructor parameters
  - Replaced non-existent `force_update_check()` method with `clear_cache()`
  - Added error handling for update check process

## [1.0.14] - 2025-07-22

### Fixed
- **Method Visibility Error**: Changed `clear_scan_checkpoints()` method visibility from private to public in scanner class to prevent fatal error when clearing scan results from admin interface

## [1.0.13] - 2025-07-22

### Fixed
- **Plugin Update Critical Error**: Re-enabled GitHub updater with proper error handling to prevent fatal errors during plugin updates
- **Enhanced File Validation**: Implemented multi-layer validation system to ensure only existing files are scanned, completely eliminating ghost files from scan results
- **Improved Error Handling**: Added comprehensive logging for file validation process

### Changed
- **UI Design Overhaul**: Completely redesigned interface with flat, minimal design
  - Removed all rounded corners (border-radius) for sharp, clean edges
  - Eliminated all shadows and gradients
  - Implemented minimal color palette with strong contrast
  - Flat buttons with clean typography
  - Grid-based layout with 1px borders
  - Uppercase labels with proper letter spacing

### Enhanced
- **File Scanning Logic**: 
  - Added `realpath()` validation to resolve symlinks
  - Implemented file size verification (must be > 0 bytes)
  - Enhanced broken symlink detection
  - Added duplicate file prevention using resolved paths
  - Comprehensive error logging for skipped files
- **UI Components**: Flat design for all elements including forms, tables, progress bars, and notifications

### Technical Improvements
- **Robust File Detection**: Multiple validation layers prevent ghost files from appearing in scan results
- **Enhanced Logging**: Detailed logging of file validation process for debugging
- **Performance**: Optimized file scanning with proper error handling
- **CSS Architecture**: Complete UI redesign with flat, minimal aesthetic

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
