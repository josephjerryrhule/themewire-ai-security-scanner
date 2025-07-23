<?php

/**
 * Database Connection Test for Docker/DevKinsta environments
 *
 * Run this file directly to test database connectivity
 */

// Minimal WordPress bootstrap
if (!defined('ABSPATH')) {
    $wp_root = dirname(dirname(dirname(__DIR__)));
    if (file_exists($wp_root . '/wp-config.php')) {
        require_once $wp_root . '/wp-config.php';
        require_once ABSPATH . 'wp-includes/wp-db.php';
    } else {
        die('WordPress installation not found. Please run this from within WordPress.');
    }
}

echo "<h1>ThemeWire Security Scanner - Database Test</h1>\n";
echo "<p>Testing database connection for Docker/DevKinsta compatibility...</p>\n";

// Include our database class
require_once __DIR__ . '/includes/class-database.php';

try {
    // Initialize database
    $database = new Themewire_Security_Database();

    // Test connection
    $test_result = $database->test_database_connection();

    if ($test_result['success']) {
        echo "<div style='color: green; background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0; border-radius: 4px;'>";
        echo "<strong>✅ Database Connection: SUCCESS</strong><br>";
        echo "Message: " . htmlspecialchars($test_result['message']) . "<br>";
        echo "MySQL Version: " . htmlspecialchars($test_result['mysql_version']) . "<br>";
        echo "Table Prefix: " . htmlspecialchars($test_result['table_prefix']) . "<br>";
        echo "</div>";

        // Check table status
        echo "<h2>Table Status:</h2>";
        foreach ($test_result['tables_exist'] as $table => $exists) {
            $status = $exists ? '✅ EXISTS' : '❌ MISSING';
            $color = $exists ? 'green' : 'red';
            echo "<p style='color: $color;'>$table: $status</p>";
        }

        // Test dashboard stats
        echo "<h2>Dashboard Statistics Test:</h2>";
        $stats = $database->get_dashboard_stats();
        echo "<pre>" . print_r($stats, true) . "</pre>";

        // Test issue counts
        echo "<h2>Issue Counts Test:</h2>";
        $issue_counts = $database->get_issue_counts();
        echo "<pre>" . print_r($issue_counts, true) . "</pre>";
    } else {
        echo "<div style='color: red; background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0; border-radius: 4px;'>";
        echo "<strong>❌ Database Connection: FAILED</strong><br>";
        echo "Error: " . htmlspecialchars($test_result['message']);
        echo "</div>";
    }
} catch (Exception $e) {
    echo "<div style='color: red; background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0; border-radius: 4px;'>";
    echo "<strong>❌ Error:</strong> " . htmlspecialchars($e->getMessage());
    echo "</div>";
}

// Test global $wpdb directly
echo "<h2>Direct WordPress Database Test:</h2>";
global $wpdb;
if ($wpdb) {
    $test_query = $wpdb->get_var("SELECT 1");
    if ($test_query === '1') {
        echo "<p style='color: green;'>✅ WordPress $wpdb connection working</p>";
        echo "<p>Database Name: " . $wpdb->dbname . "</p>";
        echo "<p>Database Host: " . $wpdb->dbhost . "</p>";
        echo "<p>Table Prefix: " . $wpdb->prefix . "</p>";
    } else {
        echo "<p style='color: red;'>❌ WordPress $wpdb connection failed</p>";
        echo "<p>Error: " . $wpdb->last_error . "</p>";
    }
} else {
    echo "<p style='color: red;'>❌ WordPress $wpdb not available</p>";
}

echo "<hr>";
echo "<p><strong>Environment Detection:</strong></p>";
echo "<p>PHP Version: " . PHP_VERSION . "</p>";
echo "<p>WordPress Path: " . (defined('ABSPATH') ? ABSPATH : 'Not defined') . "</p>";
echo "<p>Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "</p>";

// Docker detection
if (file_exists('/.dockerenv') || getenv('DOCKER_CONTAINER')) {
    echo "<p style='color: blue;'>🐳 Docker environment detected</p>";
}

echo "<p><em>Test completed at " . date('Y-m-d H:i:s') . "</em></p>";
