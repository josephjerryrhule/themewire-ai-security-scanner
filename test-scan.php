<?php
// Simple test to trigger scan processing
echo "Testing scan processing...\n";

// Simulate WordPress environment minimally
define('ABSPATH', '/www/kinsta/public/kwameamfo/');
define('WP_PLUGIN_DIR', ABSPATH . 'wp-content/plugins');
define('DAY_IN_SECONDS', 86400);

// Mock WordPress functions that are needed
function get_transient($key)
{
    // Simulate getting transient from file
    $file = "/tmp/transient_$key.json";
    if (file_exists($file)) {
        $data = file_get_contents($file);
        return json_decode($data, true);
    }
    return false;
}

function set_transient($key, $value, $timeout)
{
    // Simulate setting transient to file
    $file = "/tmp/transient_$key.json";
    file_put_contents($file, json_encode($value));
    return true;
}

function get_option($key, $default = '')
{
    return $default;
}

function __($text, $domain = '')
{
    return $text;
}

// Include the scanner class
require_once 'includes/class-scanner.php';

$scanner = new Themewire_Security_Scanner();

// Check scan status
echo "Checking scan status...\n";
$status = $scanner->get_scan_status();
print_r($status);

if ($status['success'] && $status['status'] === 'running') {
    echo "\nProcessing scan chunk...\n";
    $result = $scanner->process_optimized_scan_chunk();
    print_r($result);

    echo "\nUpdated scan status...\n";
    $status = $scanner->get_scan_status();
    print_r($status);
} else {
    echo "No active scan found or scan not running.\n";
}
