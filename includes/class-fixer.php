<?php

/**
 * The issue fixing functionality.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Fixer
{

    /**
     * Database instance
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Database    $database
     */
    private $database;

    /**
     * Quarantine directory
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $quarantine_dir
     */
    private $quarantine_dir;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     */
    public function __construct()
    {
        $this->database = new Themewire_Security_Database();

        // Create quarantine directory if it doesn't exist
        $upload_dir = wp_upload_dir();
        $this->quarantine_dir = $upload_dir['basedir'] . '/themewire-security-quarantine';

        if (!file_exists($this->quarantine_dir)) {
            wp_mkdir_p($this->quarantine_dir);

            // Add index.php to prevent directory listing
            file_put_contents($this->quarantine_dir . '/index.php', '<?php // Silence is golden');

            // Add .htaccess to prevent access to files
            file_put_contents($this->quarantine_dir . '/.htaccess', 'Deny from all');
        }
    }

    /**
     * Fix an issue
     *
     * @since    1.0.0
     * @param    int       $scan_id          The scan ID
     * @param    string    $file_path        Path to the file
     * @param    string    $suggested_fix    The suggested fix type
     * @return   array     Result of the fix operation
     */
    public function fix_issue($scan_id, $file_path, $suggested_fix)
    {
        if (!file_exists($file_path)) {
            return array(
                'success' => false,
                'message' => __('File does not exist', 'themewire-security')
            );
        }

        switch ($suggested_fix) {
            case 'quarantine':
                return $this->quarantine_file($scan_id, $file_path);

            case 'delete':
                return $this->delete_file($scan_id, $file_path);

            case 'fix':
                return $this->attempt_to_fix_file($scan_id, $file_path);

            default:
                return array(
                    'success' => false,
                    'message' => __('Unknown fix type', 'themewire-security')
                );
        }
    }

    /**
     * Fix issue by issue ID
     *
     * @since    1.0.0
     * @param    int       $issue_id    The issue ID
     * @return   array     Result of the fix operation
     */
    public function fix_issue_by_id($issue_id)
    {
        global $wpdb;

        // Get issue details
        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ), ARRAY_A);

        if (!$issue) {
            return array(
                'success' => false,
                'message' => __('Issue not found', 'themewire-security')
            );
        }

        // Determine the appropriate fix based on suggested_fix or issue type
        $fix_type = $issue['suggested_fix'];

        if (empty($fix_type)) {
            // If no suggested fix, determine based on issue type
            switch ($issue['issue_type']) {
                case 'suspicious_code':
                case 'php_in_uploads':
                    $fix_type = 'quarantine';
                    break;
                case 'core_file_modified':
                case 'core_file_missing':
                    // Use restore for core files
                    return $this->restore_core_file($issue['scan_id'], $issue['file_path']);
                default:
                    $fix_type = 'quarantine';
            }
        }

        $result = $this->fix_issue(
            $issue['scan_id'],
            $issue['file_path'],
            $fix_type
        );

        if ($result['success']) {
            $this->database->mark_issue_as_fixed($issue_id);
        }

        return $result;
    }

    /**
     * Quarantine a file
     *
     * @since    1.0.0
     * @param    int       $scan_id      The scan ID
     * @param    string    $file_path    Path to the file
     * @return   array     Result of the quarantine operation
     */
    public function quarantine_file($scan_id, $file_path)
    {
        if (!file_exists($file_path)) {
            return array(
                'success' => false,
                'message' => __('File does not exist', 'themewire-security')
            );
        }

        // Generate a unique filename for quarantine
        $filename = md5($file_path . time()) . '.quarantine';
        $quarantine_path = $this->quarantine_dir . '/' . $filename;

        // Create metadata file
        $metadata = array(
            'original_path' => $file_path,
            'quarantine_date' => current_time('mysql'),
            'scan_id' => $scan_id,
            'file_size' => filesize($file_path),
            'file_type' => pathinfo($file_path, PATHINFO_EXTENSION)
        );

        $metadata_path = $this->quarantine_dir . '/' . $filename . '.meta';

        try {
            // Move the file to quarantine
            if (!copy($file_path, $quarantine_path)) {
                throw new Exception(__('Failed to copy file to quarantine', 'themewire-security'));
            }

            // Save metadata
            file_put_contents($metadata_path, json_encode($metadata));

            // Delete the original file
            @unlink($file_path);

            // Add .htaccess to original directory to prevent re-infection
            $this->harden_directory(dirname($file_path));

            return array(
                'success' => true,
                'message' => __('File quarantined successfully', 'themewire-security'),
                'quarantine_path' => $quarantine_path
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Delete a file
     *
     * @since    1.0.0
     * @param    int       $scan_id      The scan ID
     * @param    string    $file_path    Path to the file
     * @return   array     Result of the delete operation
     */
    public function delete_file($scan_id, $file_path)
    {
        if (!file_exists($file_path)) {
            return array(
                'success' => false,
                'message' => __('File does not exist', 'themewire-security')
            );
        }

        // Backup the file first
        $backup_result = $this->quarantine_file($scan_id, $file_path);

        if (!$backup_result['success']) {
            return array(
                'success' => false,
                'message' => __('Failed to backup file before deletion', 'themewire-security')
            );
        }

        // Delete the file
        if (unlink($file_path)) {
            // Add .htaccess to directory to prevent re-infection
            $this->harden_directory(dirname($file_path));

            return array(
                'success' => true,
                'message' => __('File deleted successfully', 'themewire-security')
            );
        } else {
            return array(
                'success' => false,
                'message' => __('Failed to delete file', 'themewire-security')
            );
        }
    }

    /**
     * Attempt to fix a file
     *
     * @since    1.0.0
     * @param    int       $scan_id      The scan ID
     * @param    string    $file_path    Path to the file
     * @return   array     Result of the fix operation
     */
    public function attempt_to_fix_file($scan_id, $file_path)
    {
        if (!file_exists($file_path)) {
            return array(
                'success' => false,
                'message' => __('File does not exist', 'themewire-security')
            );
        }

        $file_type = pathinfo($file_path, PATHINFO_EXTENSION);
        $file_content = file_get_contents($file_path);

        // Backup the file first
        $backup_result = $this->quarantine_file($scan_id, $file_path);

        if (!$backup_result['success']) {
            return array(
                'success' => false,
                'message' => __('Failed to backup file before fixing', 'themewire-security')
            );
        }

        // Attempt to fix based on file type
        switch ($file_type) {
            case 'php':
                $fixed_content = $this->fix_php_file($file_content);
                break;

            case 'js':
                $fixed_content = $this->fix_js_file($file_content);
                break;

            default:
                return array(
                    'success' => false,
                    'message' => __('Unsupported file type for fixing', 'themewire-security')
                );
        }

        // Write fixed content back to file
        if (file_put_contents($file_path, $fixed_content)) {
            return array(
                'success' => true,
                'message' => __('File fixed successfully', 'themewire-security')
            );
        } else {
            return array(
                'success' => false,
                'message' => __('Failed to write fixed content to file', 'themewire-security')
            );
        }
    }

    /**
     * Fix PHP file
     *
     * @since    1.0.0
     * @param    string    $content    File content
     * @return   string    Fixed content
     */
    private function fix_php_file($content)
    {
        // Remove eval statements with base64 decoded content
        $content = preg_replace('/eval\s*\(\s*base64_decode\s*\([^)]+\)\s*\)\s*;/i', '// Malicious code removed by Themewire Security', $content);

        // Remove system and shell exec calls
        $content = preg_replace('/(system|shell_exec|exec|passthru|popen|proc_open)\s*\([^)]+\)\s*;/i', '// Malicious code removed by Themewire Security', $content);

        // Remove obfuscated code blocks
        $content = preg_replace('/(\$[a-zA-Z0-9_]+\s*=\s*str_replace\s*\([^;]+;(\s*\$[a-zA-Z0-9_]+\s*=\s*[^;]+;){2,}\s*eval\s*\([^;]+;)/i', '// Obfuscated code removed by Themewire Security', $content);

        return $content;
    }

    /**
     * Fix JavaScript file
     *
     * @since    1.0.0
     * @param    string    $content    File content
     * @return   string    Fixed content
     */
    private function fix_js_file($content)
    {
        // Remove eval statements with encoded content
        $content = preg_replace('/eval\s*\([^;]+;/i', '// Malicious code removed by Themewire Security', $content);

        // Remove document.write with suspicious iframes
        $content = preg_replace('/document\.write\s*\(\s*[\'"][^"\']*<iframe[^"\']*[\'"]\s*\)\s*;/i', '// Malicious iframe removed by Themewire Security', $content);

        // Remove redirect code
        $content = preg_replace('/window\.location\s*=\s*[\'"][^"\']+[\'"]\s*;/i', '// Suspicious redirect removed by Themewire Security', $content);

        return $content;
    }

    /**
     * Harden a directory to prevent re-infection
     *
     * @since    1.0.0
     * @param    string    $dir    Directory path
     */
    public function harden_directory($dir)
    {
        // Don't try to harden core WordPress directories
        $wp_dirs = array(
            ABSPATH,
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
            WP_CONTENT_DIR,
            WP_PLUGIN_DIR
        );

        if (in_array($dir, $wp_dirs)) {
            return;
        }

        // Check if it's an upload directory
        $upload_dir = wp_upload_dir();
        if (strpos($dir, $upload_dir['basedir']) === 0) {
            // Add .htaccess to prevent PHP execution in uploads
            $htaccess_path = $dir . '/.htaccess';

            $htaccess_content = "<FilesMatch '\.(php|phtml|php3|php4|php5|php7|phps)$'>\n";
            $htaccess_content .= "Order Allow,Deny\n";
            $htaccess_content .= "Deny from all\n";
            $htaccess_content .= "</FilesMatch>\n";
            $htaccess_content .= "# Hardened by Themewire Security Scanner\n";

            if (!file_exists($htaccess_path)) {
                @file_put_contents($htaccess_path, $htaccess_content);
            }
        }
    }

    /**
     * Restore file from quarantine
     *
     * @since    1.0.0
     * @param    string    $quarantine_file    Quarantine file path
     * @return   array     Result of the restore operation
     */
    public function restore_from_quarantine($quarantine_file)
    {
        if (!file_exists($quarantine_file)) {
            return array(
                'success' => false,
                'message' => __('Quarantine file does not exist', 'themewire-security')
            );
        }

        // Get metadata
        $metadata_file = $quarantine_file . '.meta';

        if (!file_exists($metadata_file)) {
            return array(
                'success' => false,
                'message' => __('Quarantine metadata file does not exist', 'themewire-security')
            );
        }

        $metadata = json_decode(file_get_contents($metadata_file), true);

        if (!isset($metadata['original_path'])) {
            return array(
                'success' => false,
                'message' => __('Invalid metadata file', 'themewire-security')
            );
        }

        $original_path = $metadata['original_path'];

        // Create directory if it doesn't exist
        $original_dir = dirname($original_path);
        if (!file_exists($original_dir)) {
            wp_mkdir_p($original_dir);
        }

        // Copy file back to original location
        if (copy($quarantine_file, $original_path)) {
            return array(
                'success' => true,
                'message' => __('File restored successfully', 'themewire-security'),
                'original_path' => $original_path
            );
        } else {
            return array(
                'success' => false,
                'message' => __('Failed to restore file', 'themewire-security')
            );
        }
    }

    /**
     * Restore a WordPress core file from the official repository
     *
     * @since    1.0.2
     * @param    int       $scan_id      The scan ID
     * @param    string    $file_path    Path to the file
     * @return   array     Result of the restore operation
     */
    public function restore_core_file($scan_id, $file_path)
    {
        global $wp_version;

        // Verify this is actually a core file
        if (!$this->is_wordpress_core_file($file_path)) {
            return array(
                'success' => false,
                'message' => __('This is not a WordPress core file', 'themewire-security')
            );
        }

        // Backup the current file first
        $backup_result = $this->quarantine_file($scan_id, $file_path);

        if (!$backup_result['success']) {
            return array(
                'success' => false,
                'message' => __('Failed to backup file before restoration', 'themewire-security')
            );
        }

        // Get the relative path from WordPress root
        $relative_path = str_replace(ABSPATH, '', $file_path);

        // Download the original file from WordPress.org
        $download_url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}";

        $response = wp_remote_get($download_url, array(
            'timeout' => 30,
            'user-agent' => 'WordPress/' . $wp_version . '; ' . home_url('/'),
        ));

        if (is_wp_error($response)) {
            return array(
                'success' => false,
                'message' => sprintf(__('Failed to download core file: %s', 'themewire-security'), $response->get_error_message())
            );
        }

        if (wp_remote_retrieve_response_code($response) !== 200) {
            return array(
                'success' => false,
                'message' => __('Core file not found in WordPress repository', 'themewire-security')
            );
        }

        $file_content = wp_remote_retrieve_body($response);

        if (empty($file_content)) {
            return array(
                'success' => false,
                'message' => __('Downloaded file is empty', 'themewire-security')
            );
        }

        // Write the original content to the file
        if (file_put_contents($file_path, $file_content)) {
            return array(
                'success' => true,
                'message' => __('WordPress core file restored successfully', 'themewire-security')
            );
        } else {
            return array(
                'success' => false,
                'message' => __('Failed to write restored file', 'themewire-security')
            );
        }
    }

    /**
     * Check if a file is a WordPress core file
     *
     * @since    1.0.2
     * @param    string    $file_path    Path to the file
     * @return   boolean   True if it's a core file
     */
    private function is_wordpress_core_file($file_path)
    {
        $relative_path = str_replace(ABSPATH, '', $file_path);

        // Core directories
        $core_dirs = array(
            'wp-admin/',
            'wp-includes/',
        );

        // Core files in root
        $core_files = array(
            'index.php',
            'wp-activate.php',
            'wp-blog-header.php',
            'wp-comments-post.php',
            'wp-config-sample.php',
            'wp-cron.php',
            'wp-links-opml.php',
            'wp-load.php',
            'wp-login.php',
            'wp-mail.php',
            'wp-settings.php',
            'wp-signup.php',
            'wp-trackback.php',
            'xmlrpc.php'
        );

        // Check if it's a core file in root
        if (in_array($relative_path, $core_files)) {
            return true;
        }

        // Check if it's in a core directory
        foreach ($core_dirs as $dir) {
            if (strpos($relative_path, $dir) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate plugin file integrity
     *
     * @since    1.0.2
     * @param    string    $file_path    Path to the plugin file
     * @return   array     Validation result
     */
    public function validate_plugin_file($file_path)
    {
        // Get plugin directory
        $plugin_dir = dirname($file_path);
        $plugin_name = basename($plugin_dir);

        // Check if it's from WordPress.org repository
        $plugin_data = $this->get_plugin_data_from_wordpress_org($plugin_name);

        if ($plugin_data) {
            return $this->validate_against_wordpress_org($file_path, $plugin_data);
        }

        // If not from WordPress.org, do advanced malware pattern analysis
        return $this->advanced_malware_analysis($file_path);
    }

    /**
     * Get plugin data from WordPress.org API
     *
     * @since    1.0.2
     * @param    string    $plugin_slug    Plugin slug
     * @return   array|false    Plugin data or false
     */
    private function get_plugin_data_from_wordpress_org($plugin_slug)
    {
        $api_url = "https://api.wordpress.org/plugins/info/1.0/{$plugin_slug}.json";

        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);

        return $data ?: false;
    }

    /**
     * Validate file against WordPress.org version
     *
     * @since    1.0.2
     * @param    string    $file_path      Path to the file
     * @param    array     $plugin_data    Plugin data from WordPress.org
     * @return   array     Validation result
     */
    private function validate_against_wordpress_org($file_path, $plugin_data)
    {
        // For now, we'll just do advanced malware analysis
        // In the future, we could download and compare against the official version
        return $this->advanced_malware_analysis($file_path);
    }

    /**
     * Advanced malware pattern analysis for custom themes/plugins
     *
     * @since    1.0.2
     * @param    string    $file_path    Path to the file
     * @return   array     Analysis result
     */
    public function advanced_malware_analysis($file_path)
    {
        $file_content = file_get_contents($file_path);

        if ($file_content === false) {
            return array(
                'is_malicious' => false,
                'confidence' => 0,
                'indicators' => array()
            );
        }

        $indicators = array();
        $confidence = 0;

        // Advanced malware patterns
        $high_risk_patterns = array(
            'eval\s*\(\s*base64_decode' => 'Base64 encoded eval execution',
            'eval\s*\(\s*gzinflate' => 'Compressed eval execution',
            'eval\s*\(\s*str_rot13' => 'ROT13 obfuscated eval',
            'eval\s*\(\s*\$_POST' => 'POST data execution',
            'eval\s*\(\s*\$_GET' => 'GET data execution',
            'eval\s*\(\s*\$_REQUEST' => 'REQUEST data execution',
            'system\s*\(\s*\$_' => 'System command from user input',
            'exec\s*\(\s*\$_' => 'Exec command from user input',
            'shell_exec\s*\(\s*\$_' => 'Shell exec from user input',
            'passthru\s*\(\s*\$_' => 'Passthru from user input',
            'file_get_contents\s*\(\s*[\'"]https?://' => 'Remote file inclusion',
            'file_put_contents\s*\([^,]+,\s*file_get_contents\s*\(\s*[\'"]https?://' => 'Remote file download',
            'preg_replace\s*\(\s*[\'"][^\'\"]*\/[^\'\"]*e[^\'\"]*[\'"]' => 'Preg replace with eval modifier',
            'create_function\s*\(' => 'Dynamic function creation',
            'assert\s*\(\s*\$_' => 'Assert with user input',
            '\$\{[^}]*\}' => 'Variable variable usage',
            '\\\\x[0-9a-fA-F]{2}' => 'Hexadecimal encoding',
            'chr\s*\(\s*\d+\s*\)\s*\.' => 'Character concatenation obfuscation',
        );

        $medium_risk_patterns = array(
            'base64_decode\s*\(' => 'Base64 decode usage',
            'gzinflate\s*\(' => 'Gzip inflate usage',
            'gzuncompress\s*\(' => 'Gzip uncompress usage',
            'str_rot13\s*\(' => 'ROT13 usage',
            'eval\s*\(' => 'Eval usage',
            'system\s*\(' => 'System command execution',
            'exec\s*\(' => 'Command execution',
            'shell_exec\s*\(' => 'Shell command execution',
            'passthru\s*\(' => 'Passthru execution',
            'popen\s*\(' => 'Popen usage',
            'proc_open\s*\(' => 'Process open usage',
            'include\s*\(\s*\$_' => 'Dynamic include',
            'require\s*\(\s*\$_' => 'Dynamic require',
            'include_once\s*\(\s*\$_' => 'Dynamic include_once',
            'require_once\s*\(\s*\$_' => 'Dynamic require_once',
        );

        // Check high risk patterns
        foreach ($high_risk_patterns as $pattern => $description) {
            if (preg_match('/' . $pattern . '/i', $file_content)) {
                $indicators[] = $description;
                $confidence += 30;
            }
        }

        // Check medium risk patterns
        foreach ($medium_risk_patterns as $pattern => $description) {
            if (preg_match('/' . $pattern . '/i', $file_content)) {
                $indicators[] = $description;
                $confidence += 15;
            }
        }

        // Check for obfuscation techniques
        if ($this->is_heavily_obfuscated($file_content)) {
            $indicators[] = 'Code appears to be heavily obfuscated';
            $confidence += 25;
        }

        // Check for suspicious variable names
        $suspicious_vars = array('\$[a-zA-Z]*[0-9]{3,}', '\$_+[a-zA-Z]', '\$[a-zA-Z]*_+[a-zA-Z]*_+');
        foreach ($suspicious_vars as $pattern) {
            if (preg_match('/' . $pattern . '/', $file_content)) {
                $indicators[] = 'Suspicious variable naming patterns';
                $confidence += 10;
                break;
            }
        }

        // Check for long encoded strings
        if (preg_match('/(\'|")([\w+\/=]{100,})(\'|")/', $file_content)) {
            $indicators[] = 'Contains long encoded strings';
            $confidence += 20;
        }

        // Check for iframe injections
        if (preg_match('/<iframe[^>]*src\s*=\s*[\'"][^\'\"]*[\'"][^>]*>/i', $file_content)) {
            $indicators[] = 'Contains iframe tags (potential injection)';
            $confidence += 25;
        }

        // Cap confidence at 100
        $confidence = min(100, $confidence);

        return array(
            'is_malicious' => $confidence >= 50,
            'confidence' => $confidence,
            'indicators' => $indicators
        );
    }

    /**
     * Check if content is heavily obfuscated
     *
     * @since    1.0.2
     * @param    string    $content    Content to analyze
     * @return   boolean   True if heavily obfuscated
     */
    private function is_heavily_obfuscated($content)
    {
        // Check for very long lines
        if (preg_match('/^.{500,}$/m', $content)) {
            return true;
        }

        // Check ratio of special characters
        $special_chars = preg_match_all('/[\^\$\*\(\)\[\]\{\}\?\+\.\\\\]/', $content);
        $total_length = strlen($content);

        if ($total_length > 0 && ($special_chars / $total_length) > 0.15) {
            return true;
        }

        // Check for excessive concatenation
        if (preg_match_all('/\s*\.\s*/', $content) > ($total_length / 100)) {
            return true;
        }

        return false;
    }
}
