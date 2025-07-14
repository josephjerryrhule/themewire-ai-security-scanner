<?php
/**
 * The issue fixing functionality.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Fixer {

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
    public function __construct() {
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
    public function fix_issue($scan_id, $file_path, $suggested_fix) {
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
    public function fix_issue_by_id($issue_id) {
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
        
        $result = $this->fix_issue(
            $issue['scan_id'],
            $issue['file_path'],
            $issue['suggested_fix']
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
    public function quarantine_file($scan_id, $file_path) {
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
    public function delete_file($scan_id, $file_path) {
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
    public function attempt_to_fix_file($scan_id, $file_path) {
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
    private function fix_php_file($content) {
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
    private function fix_js_file($content) {
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
    public function harden_directory($dir) {
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
    public function restore_from_quarantine($quarantine_file) {
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
}