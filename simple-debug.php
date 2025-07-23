<?php

/**
 * Simple debug script to test file discovery without WordPress loading
 */

echo "=== Simple File Discovery Debug ===\n";

// Test basic file discovery from the WordPress root
$wordpress_root = realpath('../../../');
echo "WordPress root: $wordpress_root\n";

// Test if we can find core files
$core_files = [];
$core_patterns = [
    'wp-admin/index.php',
    'wp-includes/version.php',
    'wp-content/index.php',
    'index.php'
];

echo "\n--- Testing Core File Discovery ---\n";
foreach ($core_patterns as $pattern) {
    $file_path = $wordpress_root . '/' . $pattern;
    if (file_exists($file_path)) {
        $core_files[] = $file_path;
        echo "✓ Found: $pattern\n";
    } else {
        echo "✗ Missing: $pattern\n";
    }
}

// Test plugin file discovery
echo "\n--- Testing Plugin File Discovery ---\n";
$plugins_dir = $wordpress_root . '/wp-content/plugins';
if (is_dir($plugins_dir)) {
    $plugin_files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($plugins_dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );

    $count = 0;
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $plugin_files[] = $file->getPathname();
            $count++;
            if ($count <= 10) { // Show first 10
                echo "✓ Found plugin file: " . $file->getFilename() . "\n";
            }
        }
    }
    echo "Total plugin PHP files found: $count\n";
} else {
    echo "✗ Plugins directory not found: $plugins_dir\n";
}

// Test theme file discovery
echo "\n--- Testing Theme File Discovery ---\n";
$themes_dir = $wordpress_root . '/wp-content/themes';
if (is_dir($themes_dir)) {
    $theme_files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($themes_dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );

    $count = 0;
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $theme_files[] = $file->getPathname();
            $count++;
            if ($count <= 10) { // Show first 10
                echo "✓ Found theme file: " . $file->getFilename() . "\n";
            }
        }
    }
    echo "Total theme PHP files found: $count\n";
} else {
    echo "✗ Themes directory not found: $themes_dir\n";
}

// Test uploads directory
echo "\n--- Testing Uploads Directory Discovery ---\n";
$uploads_dir = $wordpress_root . '/wp-content/uploads';
if (is_dir($uploads_dir)) {
    $upload_files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );

    $count = 0;
    $suspicious_count = 0;
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $count++;
            // Check for suspicious files in uploads
            if ($file->getExtension() === 'php') {
                $suspicious_count++;
                echo "⚠ Suspicious PHP file in uploads: " . $file->getFilename() . "\n";
            }
        }
    }
    echo "Total upload files found: $count\n";
    echo "Suspicious PHP files in uploads: $suspicious_count\n";
} else {
    echo "✗ Uploads directory not found: $uploads_dir\n";
}

// Test basic malware pattern detection
echo "\n--- Testing Basic Pattern Detection ---\n";
$malware_patterns = [
    '/eval\s*\(\s*base64_decode/',
    '/system\s*\(\s*\$_/',
    '/exec\s*\(\s*\$_/',
    '/shell_exec\s*\(\s*\$_/',
    '/passthru\s*\(\s*\$_/',
    '/\$_POST\[.*\]\s*\(\s*\$_POST/',
    '/\$_GET\[.*\]\s*\(\s*\$_GET/',
    '/file_get_contents\s*\(\s*["\']https?:\/\//',
    '/curl_exec\s*\(\s*\$/',
    '/fwrite\s*\(\s*fopen/',
    '/base64_decode\s*\(\s*\$_/',
    '/<\?php\s+\$\w+\s*=\s*[\'"]\w+[\'"];\s*eval/',
    '/\$\w+\s*=\s*[\'"][a-zA-Z0-9+\/=]{50,}[\'"];\s*eval/',
    '/wp_remote_get\s*\(\s*["\']https?:\/\/[^"\']+\.php/',
    '/add_action\s*\(\s*["\']wp_footer[\'"],\s*function/'
];

// Test on some actual files
$test_files = array_merge(
    array_slice($core_files, 0, 3),
    array_slice($plugin_files ?? [], 0, 3),
    array_slice($theme_files ?? [], 0, 3)
);

foreach ($test_files as $file) {
    if (file_exists($file) && is_readable($file)) {
        $content = file_get_contents($file);
        $found_patterns = 0;

        foreach ($malware_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $found_patterns++;
            }
        }

        $relative_path = str_replace($wordpress_root, '', $file);
        if ($found_patterns > 0) {
            echo "⚠ Found $found_patterns suspicious patterns in: $relative_path\n";
        } else {
            echo "✓ Clean file: $relative_path\n";
        }
    }
}

echo "\n=== Debug Summary ===\n";
echo "Core files found: " . count($core_files) . "\n";
echo "Plugin files found: " . ($count ?? 0) . "\n";
echo "Total files that could be scanned: " . (count($core_files) + ($count ?? 0)) . "\n";
echo "\nIf the scanner shows 0 files, the issue is likely:\n";
echo "1. Database connection failure (WordPress can't load)\n";
echo "2. Plugin not properly saving scan results to database\n";
echo "3. Scanner not being triggered properly\n";
