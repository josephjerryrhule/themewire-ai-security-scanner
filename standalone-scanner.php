<?php

/**
 * Standalone Emergency Malware Scanner
 * Works without WordPress database or other dependencies
 */

class Emergency_Malware_Scanner
{
    private $last_detected_patterns = array();

    /**
     * Scan WordPress installation for malware threats.
     *
     * @param    string    $wordpress_root    Path to WordPress root directory
     * @return   array     Scan results with detected threats
     */
    public function scan($wordpress_root = null)
    {
        if ($wordpress_root === null) {
            $wordpress_root = realpath('../../../');
        }

        $results = array(
            'scan_time' => date('Y-m-d H:i:s'),
            'files_scanned' => 0,
            'threats_found' => 0,
            'threats' => array(),
            'summary' => array(
                'high_risk' => 0,
                'medium_risk' => 0,
                'low_risk' => 0
            )
        );

        echo "🔍 Scanning WordPress root: $wordpress_root\n\n";

        // Scan critical directories
        $directories_to_scan = array(
            $wordpress_root . '/wp-content/uploads',
            $wordpress_root . '/wp-content/themes',
            $wordpress_root . '/wp-content/plugins',
            $wordpress_root . '/wp-admin',
            $wordpress_root . '/wp-includes'
        );

        foreach ($directories_to_scan as $directory) {
            if (is_dir($directory)) {
                $dir_name = basename($directory);
                echo "📂 Scanning $dir_name...\n";
                $this->scan_directory($directory, $wordpress_root, $results);
            }
        }

        // Generate summary
        $results['summary']['total_threats'] = $results['threats_found'];
        $results['status'] = $results['threats_found'] > 0 ? 'THREATS_DETECTED' : 'CLEAN';

        return $results;
    }

    /**
     * Scan a directory recursively.
     */
    private function scan_directory($directory, $wordpress_root, &$results)
    {
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $filepath = $file->getPathname();
                    $extension = strtolower($file->getExtension());

                    // Focus on PHP files and other executable types
                    if (in_array($extension, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'js', 'html', 'htm'))) {
                        $results['files_scanned']++;

                        // Check file for malware
                        $threat_level = $this->check_file_for_malware($filepath, $wordpress_root);

                        if ($threat_level > 0) {
                            $relative_path = str_replace($wordpress_root, '', $filepath);
                            $threat_info = array(
                                'file' => $relative_path,
                                'full_path' => $filepath,
                                'risk_level' => $threat_level >= 75 ? 'HIGH' : ($threat_level >= 40 ? 'MEDIUM' : 'LOW'),
                                'score' => $threat_level,
                                'detected_patterns' => $this->last_detected_patterns,
                                'file_size' => filesize($filepath),
                                'modified_time' => date('Y-m-d H:i:s', filemtime($filepath))
                            );

                            $results['threats'][] = $threat_info;
                            $results['threats_found']++;

                            // Update summary counts
                            if ($threat_level >= 75) {
                                $results['summary']['high_risk']++;
                            } elseif ($threat_level >= 40) {
                                $results['summary']['medium_risk']++;
                            } else {
                                $results['summary']['low_risk']++;
                            }

                            // Show immediate feedback for high-risk files
                            if ($threat_level >= 75) {
                                echo "🚨 HIGH RISK: $relative_path (Score: $threat_level)\n";
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            echo "⚠️  Error scanning directory $directory: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Check file for malware patterns.
     */
    private function check_file_for_malware($filepath, $wp_root)
    {
        $this->last_detected_patterns = array();

        if (!is_readable($filepath) || filesize($filepath) > 5 * 1024 * 1024) { // Skip files > 5MB
            return 0;
        }

        $content = file_get_contents($filepath);
        if ($content === false) {
            return 0;
        }

        $threat_score = 0;

        // Enhanced malware patterns with scores
        $malware_patterns = array(
            'eval\s*\(\s*base64_decode' => 75,
            'eval\s*\(\s*gzinflate' => 70,
            'eval\s*\(\s*str_rot13' => 65,
            'system\s*\(\s*\$_' => 80,
            'exec\s*\(\s*\$_' => 80,
            'shell_exec\s*\(\s*\$_' => 80,
            'passthru\s*\(\s*\$_' => 75,
            'file_get_contents\s*\(\s*["\']https?:\/\/' => 60,
            'base64_decode\s*\(\s*\$_' => 70,
            'unserialize\s*\(\s*\$' => 65,
            'function\s+\w+\(\$\w+,\s*\$\w+,\s*\$\w+\)\s*\{\s*global\s+\$\w+;' => 80,
            'chr\(\d+\)\s*\.\s*chr\(\d+\)' => 60,
            '\$\w+\s*=\s*chr\(\d+\)' => 45,
            'array_map\s*\(\s*["\'][\w]+[\'"]' => 55,
            'str_rot13\s*\(\s*base64_decode' => 85,
            'rawurldecode\s*\(' => 35,
            'implode\s*\(\s*["\'][\'"]' => 40,
            '\$_SERVER\s*\[\s*["\']DOCUMENT_ROOT[\'"]' => 45,
            'glob\s*\(\s*\$\w+\s*\.\s*["\']\/\*[\'"]' => 50,
            'file_put_contents\s*\([^,]*\$_' => 70,
            'fwrite\s*\(\s*fopen\s*\([^,]*\$_' => 65,
            '\$\w+\s*\(\s*\$\w+\s*\^\s*\$\w+\)' => 75,
            'foreach\s*\(\s*\$_POST\s+as\s+\$\w+\s*=>' => 60,
            '\$_POST\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(' => 75,
            '\$_GET\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(' => 75,
            'create_function\s*\(' => 70,
            'preg_replace\s*\([^,]*\/e' => 75,
            'assert\s*\(\s*\$_' => 70,
            'wp_remote_get\s*\(\s*["\']https?:\/\/[^"\']+\.php' => 55,
            'add_action\s*\(\s*["\']wp_footer[\'"],\s*function' => 50
        );

        // Check each pattern
        foreach ($malware_patterns as $pattern => $score) {
            if (preg_match('/' . $pattern . '/i', $content)) {
                $threat_score += $score;
                $this->last_detected_patterns[] = "Pattern: $pattern (Score: +$score)";
            }
        }

        // Heuristic checks
        $chr_count = preg_match_all('/chr\(\d+\)/', $content);
        if ($chr_count > 20) {
            $threat_score += 50;
            $this->last_detected_patterns[] = "Heavy chr() obfuscation ($chr_count instances) (Score: +50)";
        }

        // Check for XOR operations (encryption)
        if (preg_match('/\^\s*\$/', $content)) {
            $threat_score += 25;
            $this->last_detected_patterns[] = "XOR operations detected (Score: +25)";
        }

        // Variable function calls
        if (preg_match('/\$\w+\s*\(\s*\$/', $content)) {
            $threat_score += 30;
            $this->last_detected_patterns[] = "Variable function calls (Score: +30)";
        }

        // Suspicious file locations
        $relative_path = str_replace($wp_root, '', $filepath);
        if (strpos($relative_path, '/wp-content/uploads/') !== false && pathinfo($filepath, PATHINFO_EXTENSION) === 'php') {
            $threat_score += 60;
            $this->last_detected_patterns[] = "PHP file in uploads directory (Score: +60)";
        }

        // Large base64 strings
        if (preg_match('/[\'"][A-Za-z0-9+\/=]{200,}[\'"]/', $content)) {
            $threat_score += 40;
            $this->last_detected_patterns[] = "Large base64 string detected (Score: +40)";
        }

        // Multiple suspicious function calls in same file
        $suspicious_functions = array('eval', 'exec', 'system', 'shell_exec', 'passthru', 'file_get_contents', 'fwrite', 'file_put_contents');
        $function_count = 0;
        foreach ($suspicious_functions as $func) {
            if (preg_match('/' . $func . '\s*\(/', $content)) {
                $function_count++;
            }
        }
        if ($function_count >= 3) {
            $threat_score += 35;
            $this->last_detected_patterns[] = "Multiple suspicious functions ($function_count) (Score: +35)";
        }

        // Cap the score at 100
        return min($threat_score, 100);
    }
}

// Run the scanner
echo "=== Emergency ThemeWire Security Scanner ===\n";
echo "This scanner works even when WordPress database is unavailable.\n\n";

try {
    $scanner = new Emergency_Malware_Scanner();
    $results = $scanner->scan();

    // Display results
    echo "\n=== SCAN RESULTS ===\n";
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
        echo str_repeat("=", 100) . "\n";

        foreach ($results['threats'] as $i => $threat) {
            echo "\n" . ($i + 1) . ". " . $threat['file'] . "\n";
            echo "   Risk Level: " . $threat['risk_level'] . " (Score: " . $threat['score'] . ")\n";
            echo "   File Size: " . number_format($threat['file_size']) . " bytes\n";
            echo "   Modified: " . $threat['modified_time'] . "\n";

            if (!empty($threat['detected_patterns'])) {
                echo "   Detected Issues:\n";
                foreach ($threat['detected_patterns'] as $pattern) {
                    echo "     • " . $pattern . "\n";
                }
            }
            echo str_repeat("-", 100) . "\n";
        }

        echo "\n🔥 IMMEDIATE ACTION REQUIRED:\n";
        echo "1. BACKUP your site immediately\n";
        echo "2. REMOVE the suspicious files listed above\n";
        echo "3. CHANGE all passwords (WordPress, hosting, FTP)\n";
        echo "4. UPDATE WordPress core, themes, and plugins\n";
        echo "5. SCAN again to ensure all threats are removed\n\n";

        // Show deletion commands for HIGH risk files only
        echo "🗑️  Deletion commands for HIGH RISK files (USE WITH EXTREME CAUTION):\n";
        foreach ($results['threats'] as $threat) {
            if ($threat['risk_level'] === 'HIGH') {
                echo "rm \"" . $threat['full_path'] . "\"\n";
            }
        }
    } else {
        echo "✅ No immediate security threats detected.\n";
        echo "Your WordPress installation appears clean.\n";
    }

    echo "\n" . str_repeat("=", 100) . "\n";
    echo "Emergency scan completed successfully!\n";
} catch (Exception $e) {
    echo "❌ Scanner error: " . $e->getMessage() . "\n";
    echo "This may indicate a more serious security compromise.\n";
}
