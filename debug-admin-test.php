<?php

/**
 * Simple debug test to run from WordPress admin to check scan functionality
 * Access this via: /wp-admin/admin.php?page=twss-debug-scan
 */

// Add to WordPress admin
add_action('admin_menu', function () {
    add_submenu_page(
        'tools.php',
        'TWSS Debug Scan',
        'TWSS Debug Scan',
        'manage_options',
        'twss-debug-scan',
        'twss_debug_scan_page'
    );
});

function twss_debug_scan_page()
{
    echo '<div class="wrap">';
    echo '<h1>ThemeWire Security Scanner Debug</h1>';

    try {
        // Load plugin classes
        require_once(TWSS_PLUGIN_DIR . 'includes/class-database.php');
        require_once(TWSS_PLUGIN_DIR . 'includes/class-scanner.php');
        require_once(TWSS_PLUGIN_DIR . 'includes/class-logger.php');

        $database = new Themewire_Security_Database();
        $logger = new Themewire_Security_Logger();
        $scanner = new Themewire_Security_Scanner($database, null, null, $logger, null);

        echo '<h2>1. Database Connection Test</h2>';
        $connection_test = $database->test_database_connection();
        if ($connection_test['success']) {
            echo '<p style="color: green;">✓ Database connection successful</p>';
        } else {
            echo '<p style="color: red;">✗ Database connection failed: ' . esc_html($connection_test['error']) . '</p>';
        }

        echo '<h2>2. File Inventory Test</h2>';

        // Use reflection to access private method
        $reflection = new ReflectionClass($scanner);
        $method = $reflection->getMethod('calculate_scan_inventory');
        $method->setAccessible(true);

        $inventory = $method->invoke($scanner);

        echo '<p><strong>Inventory Results:</strong></p>';
        echo '<ul>';
        echo '<li>Total files: ' . intval($inventory['total_files']) . '</li>';
        echo '<li>Stage breakdown:</li>';
        echo '<ul>';
        foreach ($inventory['stage_totals'] as $stage => $count) {
            echo '<li>' . esc_html($stage) . ': ' . intval($count) . ' files</li>';
        }
        echo '</ul></ul>';

        echo '<h2>3. Recent Scans</h2>';
        $recent_scans = $database->get_recent_scans(5);
        if ($recent_scans) {
            echo '<table class="wp-list-table widefat fixed striped">';
            echo '<thead><tr><th>Scan ID</th><th>Status</th><th>Total Files</th><th>Issues Found</th><th>Date</th></tr></thead>';
            echo '<tbody>';
            foreach ($recent_scans as $scan) {
                echo '<tr>';
                echo '<td>' . intval($scan['id']) . '</td>';
                echo '<td>' . esc_html($scan['status']) . '</td>';
                echo '<td>' . intval($scan['total_files'] ?? 0) . '</td>';
                echo '<td>' . intval($scan['issues_found'] ?? 0) . '</td>';
                echo '<td>' . esc_html($scan['scan_date']) . '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
        } else {
            echo '<p>No recent scans found.</p>';
        }

        echo '<h2>4. Dashboard Stats</h2>';
        $dashboard_stats = $database->get_dashboard_stats();
        echo '<pre>' . esc_html(print_r($dashboard_stats, true)) . '</pre>';

        echo '<h2>5. Test Small Scan</h2>';
        if (isset($_GET['run_test_scan'])) {
            echo '<p><strong>Running test scan...</strong></p>';

            // Create a test scan record
            $test_scan_id = $database->create_new_scan_record();
            echo '<p>Created test scan ID: ' . intval($test_scan_id) . '</p>';

            // Test scanning a single directory (plugin directory)
            $scan_method = $reflection->getMethod('scan_directory_recursively');
            $scan_method->setAccessible(true);

            $plugin_dir = TWSS_PLUGIN_DIR;
            $files = $scan_method->invoke($scanner, $plugin_dir);
            $php_files = array_filter($files, function ($file) {
                return pathinfo($file, PATHINFO_EXTENSION) === 'php';
            });

            echo '<p>Found ' . count($files) . ' total files, ' . count($php_files) . ' PHP files in plugin directory</p>';

            // Update the scan with file count
            $database->update_scan_total_files($test_scan_id, count($php_files));
            $database->update_scan_status($test_scan_id, 'completed');

            echo '<p>✓ Updated scan record with file count</p>';

            // Verify the update
            $test_summary = $database->get_scan_summary($test_scan_id);
            echo '<p><strong>Test scan summary:</strong></p>';
            echo '<pre>' . esc_html(print_r($test_summary, true)) . '</pre>';
        } else {
            echo '<p><a href="' . add_query_arg('run_test_scan', '1') . '" class="button button-primary">Run Test Scan</a></p>';
        }
    } catch (Exception $e) {
        echo '<div class="notice notice-error"><p><strong>Error:</strong> ' . esc_html($e->getMessage()) . '</p></div>';
        echo '<pre>' . esc_html($e->getTraceAsString()) . '</pre>';
    }

    echo '</div>';
}
