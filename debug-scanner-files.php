<?php

/**
 * Debug scanner to test file scanning functionality
 * This will help identify why 0 scanned files are being reported
 */

// WordPress bootstrap
if (!defined('ABSPATH')) {
    require_once(dirname(__FILE__) . '/../../../wp-config.php');
}

// Load plugin classes
require_once(dirname(__FILE__) . '/includes/class-database.php');
require_once(dirname(__FILE__) . '/includes/class-scanner.php');
require_once(dirname(__FILE__) . '/includes/class-logger.php');

echo "=== ThemeWire Security Scanner Debug ===\n";
echo "Date: " . date('Y-m-d H:i:s') . "\n\n";

try {
    // Initialize database and scanner
    $database = new Themewire_Security_Database();
    $logger = new Themewire_Security_Logger();
    $scanner = new Themewire_Security_Scanner($database, null, null, $logger, null);

    echo "1. Testing database connection...\n";
    $connection_test = $database->test_database_connection();
    if ($connection_test['success']) {
        echo "✓ Database connection successful\n";
    } else {
        echo "✗ Database connection failed: " . $connection_test['error'] . "\n";
        exit(1);
    }

    echo "\n2. Testing scan inventory calculation...\n";

    // Use reflection to access private method
    $reflection = new ReflectionClass($scanner);
    $method = $reflection->getMethod('calculate_scan_inventory');
    $method->setAccessible(true);

    $inventory = $method->invoke($scanner);

    echo "Inventory Results:\n";
    echo "- Total files: " . $inventory['total_files'] . "\n";
    echo "- Stage breakdown:\n";
    foreach ($inventory['stage_totals'] as $stage => $count) {
        echo "  * $stage: $count files\n";
    }

    echo "\n3. Testing directory scanning...\n";

    // Test scanning a single directory
    $scan_method = $reflection->getMethod('scan_directory_recursively');
    $scan_method->setAccessible(true);

    $test_dirs = [
        WP_PLUGIN_DIR . '/themewire-ai-security-scanner',
        get_template_directory(),
        WP_CONTENT_DIR . '/themes'
    ];

    foreach ($test_dirs as $dir) {
        if (is_dir($dir)) {
            echo "Scanning directory: $dir\n";
            $files = $scan_method->invoke($scanner, $dir);
            $php_files = array_filter($files, function ($file) {
                return pathinfo($file, PATHINFO_EXTENSION) === 'php';
            });
            echo "- Total files: " . count($files) . "\n";
            echo "- PHP files: " . count($php_files) . "\n";
            echo "- Sample files: " . implode(', ', array_slice($files, 0, 3)) . "\n\n";
        } else {
            echo "Directory not found: $dir\n\n";
        }
    }

    echo "4. Testing scan creation...\n";
    $scan_id = $database->create_new_scan_record();
    echo "✓ Created scan record with ID: $scan_id\n";

    echo "\n5. Testing scan status update...\n";
    $database->update_scan_total_files($scan_id, 999);
    echo "✓ Updated scan total files to 999\n";

    echo "\n6. Verifying database record...\n";
    $scan_summary = $database->get_scan_summary($scan_id);
    echo "Scan summary:\n";
    print_r($scan_summary);

    echo "\n7. Testing comprehensive stats...\n";
    $comprehensive_stats = $database->get_comprehensive_scan_stats($scan_id);
    echo "Comprehensive stats:\n";
    print_r($comprehensive_stats);

    echo "\n=== Debug Complete ===\n";
} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}
