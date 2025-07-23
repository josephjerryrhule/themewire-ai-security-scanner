<?php

/**
 * Debug script for testing scanner functionality
 */

// Include WordPress
require_once('../../../wp-config.php');

// Include our classes
require_once('includes/class-database.php');
require_once('includes/class-scanner.php');
require_once('includes/class-logger.php');

echo "=== ThemeWire Security Scanner Debug ===\n";

try {
    // Initialize database
    $database = new Themewire_Security_Database();
    echo "✓ Database class loaded\n";

    // Check if tables exist
    global $wpdb;
    $tables = array('twss_scans', 'twss_issues', 'twss_scan_results');
    foreach ($tables as $table) {
        $table_name = $wpdb->prefix . $table;
        $exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");
        if ($exists) {
            echo "✓ Table $table_name exists\n";
        } else {
            echo "✗ Table $table_name missing\n";
        }
    }

    // Test scanner initialization
    $scanner = new Themewire_Security_Scanner();
    echo "✓ Scanner class loaded\n";

    // Test file discovery methods
    echo "\n=== Testing File Discovery ===\n";

    // Test core files discovery
    $reflection = new ReflectionClass($scanner);
    $method = $reflection->getMethod('find_all_core_files');
    $method->setAccessible(true);
    $core_files = $method->invoke($scanner);
    echo "Core files found: " . count($core_files) . "\n";
    if (count($core_files) > 0) {
        echo "First 3 core files:\n";
        for ($i = 0; $i < min(3, count($core_files)); $i++) {
            echo "  - " . $core_files[$i] . "\n";
        }
    }

    // Test plugin files discovery
    $method = $reflection->getMethod('find_all_plugin_files');
    $method->setAccessible(true);
    $plugin_files = $method->invoke($scanner);
    echo "Plugin files found: " . count($plugin_files) . "\n";

    // Test theme files discovery
    $method = $reflection->getMethod('find_all_theme_files');
    $method->setAccessible(true);
    $theme_files = $method->invoke($scanner);
    echo "Theme files found: " . count($theme_files) . "\n";

    // Test uploads files discovery
    $method = $reflection->getMethod('find_all_upload_files');
    $method->setAccessible(true);
    $upload_files = $method->invoke($scanner);
    echo "Upload files found: " . count($upload_files) . "\n";

    $total_files = count($core_files) + count($plugin_files) + count($theme_files) + count($upload_files);
    echo "\nTOTAL FILES DISCOVERABLE: $total_files\n";

    // Check recent scans
    echo "\n=== Recent Scans ===\n";
    $recent_scans = $wpdb->get_results(
        "SELECT id, scan_date, status, total_files, issues_found FROM {$wpdb->prefix}twss_scans ORDER BY id DESC LIMIT 3",
        ARRAY_A
    );

    if (empty($recent_scans)) {
        echo "No scans found in database\n";
    } else {
        foreach ($recent_scans as $scan) {
            echo "Scan #{$scan['id']}: {$scan['scan_date']} - Status: {$scan['status']} - Files: {$scan['total_files']} - Issues: {$scan['issues_found']}\n";
        }
    }

    // Test basic pattern detection
    echo "\n=== Testing Pattern Detection ===\n";
    $test_content = '<?php eval(base64_decode("dGVzdA==")); ?>';
    $method = $reflection->getMethod('detect_basic_file_issues');
    $method->setAccessible(true);
    $issues = $method->invoke($scanner, '/test/malware.php', $test_content);
    echo "Test malware patterns detected: " . count($issues) . "\n";
    foreach ($issues as $issue) {
        echo "  - {$issue['type']}: {$issue['description']}\n";
    }
} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}

echo "\n=== Debug Complete ===\n";
