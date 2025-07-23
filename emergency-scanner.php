<?php

/**
 * Emergency scanner test - works without WordPress database
 */

echo "=== Emergency ThemeWire Security Scanner ===\n";
echo "This scanner works even when WordPress database is unavailable.\n\n";

// Include just the scanner class
require_once('includes/class-scanner.php');

try {
    // Create scanner instance
    $scanner = new Themewire_Security_Scanner();

    echo "✓ Scanner initialized successfully\n";
    echo "🔍 Starting emergency scan...\n\n";

    // Run emergency scan
    $results = $scanner->emergency_standalone_scan();

    // Display results
    echo "=== SCAN RESULTS ===\n";
    echo "Scan completed: " . $results['scan_time'] . "\n";
    echo "Files scanned: " . $results['files_scanned'] . "\n";
    echo "Threats found: " . $results['threats_found'] . "\n";
    echo "Status: " . $results['status'] . "\n\n";

    if ($results['threats_found'] > 0) {
        echo "🚨 SECURITY THREATS DETECTED! 🚨\n\n";

        echo "Risk Summary:\n";
        echo "  HIGH Risk: " . $results['summary']['high_risk'] . "\n";
        echo "  MEDIUM Risk: " . $results['summary']['medium_risk'] . "\n";
        echo "  LOW Risk: " . $results['summary']['low_risk'] . "\n\n";

        echo "Detailed Threat Report:\n";
        echo str_repeat("=", 80) . "\n";

        foreach ($results['threats'] as $i => $threat) {
            echo "\n" . ($i + 1) . ". " . $threat['file'] . "\n";
            echo "   Risk Level: " . $threat['risk_level'] . " (Score: " . $threat['score'] . ")\n";
            echo "   File Size: " . number_format($threat['file_size']) . " bytes\n";
            echo "   Modified: " . $threat['modified_time'] . "\n";

            if (!empty($threat['detected_patterns'])) {
                echo "   Detected Patterns:\n";
                foreach ($threat['detected_patterns'] as $pattern) {
                    echo "     • " . $pattern . "\n";
                }
            }
            echo str_repeat("-", 80) . "\n";
        }

        echo "\n🔥 IMMEDIATE ACTION REQUIRED:\n";
        echo "1. BACKUP your site immediately\n";
        echo "2. REMOVE the suspicious files listed above\n";
        echo "3. CHANGE all passwords (WordPress, hosting, FTP)\n";
        echo "4. UPDATE WordPress core, themes, and plugins\n";
        echo "5. SCAN again to ensure all threats are removed\n\n";

        // Show deletion commands
        echo "Quick removal commands (USE WITH CAUTION):\n";
        foreach ($results['threats'] as $threat) {
            if ($threat['risk_level'] === 'HIGH') {
                echo "rm \"" . $threat['full_path'] . "\"\n";
            }
        }
    } else {
        echo "✅ No immediate security threats detected.\n";
        echo "Your WordPress installation appears clean.\n";
    }

    echo "\n" . str_repeat("=", 80) . "\n";
    echo "Emergency scan completed successfully!\n";
} catch (Exception $e) {
    echo "❌ Scanner error: " . $e->getMessage() . "\n";
    echo "This may indicate a more serious security compromise.\n";
}
