<?php

/**
 * Real-time threat prevention and hardening functionality.
 *
 * @link       https://themewire.com
 * @since      1.0.52
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Real_Time_Protection
{

    /**
     * Database instance
     *
     * @since    1.0.52
     * @access   private
     * @var      Themewire_Security_Database    $database
     */
    private $database;

    /**
     * Logger instance
     *
     * @since    1.0.52
     * @access   private
     * @var      Themewire_Security_Logger    $logger
     */
    private $logger;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.52
     */
    public function __construct()
    {
        $this->database = new Themewire_Security_Database();
        $this->logger = new Themewire_Security_Logger();
    }

    /**
     * Initialize real-time protection with proper WordPress hook integration
     *
     * @since    1.0.52
     */
    public function init()
    {
        // Only run if protection is enabled
        if (!get_option('twss_enable_realtime_protection', false)) {
            return;
        }

        // Only run if WordPress is loaded and user has proper permissions
        if (!function_exists('add_action')) {
            return;
        }

        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks for real-time protection
     *
     * @since    1.0.52
     */
    private function init_hooks()
    {
        // File integrity monitoring
        add_action('wp_loaded', array($this, 'monitor_file_changes'));

        // Behavioral anomaly detection
        add_action('init', array($this, 'detect_suspicious_behavior'));

        // Zero-trust PHP execution in uploads
        add_action('init', array($this, 'block_php_execution_in_uploads'));

        // Rate limiting for admin actions
        add_action('wp_login', array($this, 'rate_limit_login_attempts'), 10, 2);

        // GeoIP and reputation blocking
        add_action('init', array($this, 'check_ip_reputation'));

        // Database injection protection
        add_filter('query', array($this, 'detect_sql_injection'));

        // WAF for virtual patching
        add_action('init', array($this, 'virtual_patching_waf'), 1);
    }

    /**
     * Monitor file changes for integrity violations
     *
     * @since    1.0.52
     */
    public function monitor_file_changes()
    {
        if (!get_option('twss_real_time_monitoring', false)) {
            return;
        }

        // Check for recently modified core files
        $modified_files = $this->get_recently_modified_files();

        foreach ($modified_files as $file) {
            if ($this->is_suspicious_modification($file)) {
                $this->handle_suspicious_file_change($file);
            }
        }
    }

    /**
     * Detect behavioral anomalies
     *
     * @since    1.0.52
     */
    public function detect_suspicious_behavior()
    {
        // Detect unusual process spawning
        $this->detect_process_anomalies();

        // Monitor unusual file write patterns
        $this->detect_file_write_anomalies();

        // Check for mass file modifications
        $this->detect_mass_file_changes();
    }

    /**
     * Block PHP execution in uploads directory
     *
     * @since    1.0.52
     */
    public function block_php_execution_in_uploads()
    {
        $upload_dir = wp_upload_dir();
        $htaccess_path = $upload_dir['basedir'] . '/.htaccess';

        $protection_rules = "# Themewire Security - Zero Trust PHP Protection\n";
        $protection_rules .= "<FilesMatch '\.(php|php3|php4|php5|php7|phtml|phps)$'>\n";
        $protection_rules .= "  Require all denied\n";
        $protection_rules .= "</FilesMatch>\n\n";
        $protection_rules .= "# Block dangerous file types\n";
        $protection_rules .= "<FilesMatch '\.(exe|sh|bat|cmd|scr|pif|vbs|js)$'>\n";
        $protection_rules .= "  Require all denied\n";
        $protection_rules .= "</FilesMatch>\n\n";

        if (!file_exists($htaccess_path) || !strpos(file_get_contents($htaccess_path), 'Themewire Security')) {
            file_put_contents($htaccess_path, $protection_rules, FILE_APPEND | LOCK_EX);
        }
    }

    /**
     * Rate limit login attempts and admin actions
     *
     * @since    1.0.52
     * @param    string    $user_login    Username
     * @param    WP_User   $user          User object
     */
    public function rate_limit_login_attempts($user_login, $user)
    {
        $ip = $this->get_client_ip();
        $rate_limit_key = 'twss_rate_limit_' . md5($ip);

        $attempts = get_transient($rate_limit_key);
        if ($attempts === false) {
            $attempts = 0;
        }

        $attempts++;
        set_transient($rate_limit_key, $attempts, HOUR_IN_SECONDS);

        // Block if too many attempts
        if ($attempts > 10) {
            $this->block_ip_temporarily($ip, 'Excessive login attempts');
            wp_die(__('Too many login attempts. Please try again later.', 'themewire-security'));
        }
    }

    /**
     * Check IP reputation and GeoIP blocking
     *
     * @since    1.0.52
     */
    public function check_ip_reputation()
    {
        if (!get_option('twss_ip_reputation_blocking', false)) {
            return;
        }

        $ip = $this->get_client_ip();

        // Check against known malicious IP databases
        if ($this->is_malicious_ip($ip)) {
            $this->block_ip_permanently($ip, 'Known malicious IP');
            wp_die(__('Access denied for security reasons.', 'themewire-security'));
        }

        // GeoIP blocking for high-risk countries
        if ($this->is_blocked_country($ip)) {
            $this->log_blocked_access($ip, 'GeoIP block');
            wp_die(__('Access from your location is not permitted.', 'themewire-security'));
        }
    }

    /**
     * Detect SQL injection attempts
     *
     * @since    1.0.52
     * @param    string    $query    SQL query
     * @return   string    Filtered query
     */
    public function detect_sql_injection($query)
    {
        $malicious_patterns = array(
            '/(\bUNION\b.*\bSELECT\b)/i',
            '/(\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\bOR\b.*1\s*=\s*1)/i',
            '/(\bDROP\b.*\bTABLE\b)/i',
            '/(\bINSERT\b.*\bINTO\b.*\bVALUES\b.*\(\s*\'[^\']*\'[^)]*\))/i',
            '/(\bUPDATE\b.*\bSET\b.*\bWHERE\b)/i',
            '/(\/\*.*\*\/)/i',
            '/(\-\-\s)/i',
            '/(\bEXEC\b|\bEXECUTE\b)/i'
        );

        foreach ($malicious_patterns as $pattern) {
            if (preg_match($pattern, $query)) {
                $this->handle_sql_injection_attempt($query);
                // Don't execute the query
                return 'SELECT 1 WHERE 0 = 1;'; // Safe dummy query
            }
        }

        return $query;
    }

    /**
     * Virtual patching WAF for known vulnerabilities
     *
     * @since    1.0.52
     */
    public function virtual_patching_waf()
    {
        if (!get_option('twss_virtual_patching', false)) {
            return;
        }

        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // CVE-based rules for common WordPress vulnerabilities
        $vulnerability_patterns = array(
            // SQL Injection
            '/(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b).*(\bfrom\b|\binto\b|\bwhere\b)/i',

            // XSS
            '/<script[^>]*>.*<\/script>/i',
            '/javascript:/i',
            '/on\w+\s*=/i',

            // RCE
            '/(\beval\b|\bexec\b|\bsystem\b|\bshell_exec\b|\bpassthru\b)/i',
            '/(\$_GET\[|\$_POST\[|\$_REQUEST\[).*(\beval\b|\bexec\b)/i',

            // File inclusion
            '/(\.\.\/|\.\.\\\\)/i',
            '/\b(file|http|ftp|php):\/\//i',

            // Directory traversal
            '/(\.\.\/)|(\.\.\\\\)/i',
            '/\/etc\/passwd/i',
            '/\/proc\/self\/environ/i',
        );

        $combined_input = $request_uri . ' ' . $query_string . ' ' . $user_agent;

        foreach ($vulnerability_patterns as $pattern) {
            if (preg_match($pattern, $combined_input)) {
                $this->block_malicious_request($pattern, $combined_input);
                wp_die(__('Request blocked for security reasons.', 'themewire-security'));
            }
        }
    }

    /**
     * Credential hardening with strong password enforcement
     *
     * @since    1.0.52
     */
    public function enforce_strong_passwords()
    {
        add_filter('wp_authenticate_user', array($this, 'check_password_strength'), 10, 2);
    }

    /**
     * Check password strength on login
     *
     * @since    1.0.52
     * @param    WP_User|WP_Error    $user      User object or error
     * @param    string              $password  Password
     * @return   WP_User|WP_Error    User object or error
     */
    public function check_password_strength($user, $password)
    {
        if (is_wp_error($user)) {
            return $user;
        }

        if (user_can($user, 'administrator') && !$this->is_strong_password($password)) {
            return new WP_Error('weak_password', __('Administrator accounts require strong passwords.', 'themewire-security'));
        }

        return $user;
    }

    /**
     * Dependency CVE scanning
     *
     * @since    1.0.52
     */
    public function scan_for_vulnerable_dependencies()
    {
        $plugins = get_plugins();
        $vulnerable_plugins = array();

        foreach ($plugins as $plugin_file => $plugin_data) {
            $vulnerabilities = $this->check_plugin_vulnerabilities($plugin_data['Name'], $plugin_data['Version']);
            if (!empty($vulnerabilities)) {
                $vulnerable_plugins[$plugin_file] = $vulnerabilities;
            }
        }

        if (!empty($vulnerable_plugins)) {
            $this->notify_vulnerable_dependencies($vulnerable_plugins);
        }

        return $vulnerable_plugins;
    }

    /**
     * Database scan for obfuscated injections
     *
     * @since    1.0.52
     */
    public function scan_database_for_injections()
    {
        global $wpdb;

        $suspicious_patterns = array(
            'base64_decode',
            'eval(',
            'gzinflate',
            'str_rot13',
            '<script',
            'javascript:',
            'document.write'
        );

        $tables_to_check = array(
            $wpdb->posts => array('post_content', 'post_excerpt'),
            $wpdb->options => array('option_value'),
            $wpdb->postmeta => array('meta_value'),
            $wpdb->usermeta => array('meta_value')
        );

        $injections_found = array();

        foreach ($tables_to_check as $table => $columns) {
            foreach ($columns as $column) {
                foreach ($suspicious_patterns as $pattern) {
                    $query = $wpdb->prepare(
                        "SELECT * FROM {$table} WHERE {$column} LIKE %s",
                        '%' . $wpdb->esc_like($pattern) . '%'
                    );

                    $results = $wpdb->get_results($query);
                    if (!empty($results)) {
                        $injections_found[] = array(
                            'table' => $table,
                            'column' => $column,
                            'pattern' => $pattern,
                            'count' => count($results),
                            'data' => $results
                        );
                    }
                }
            }
        }

        return $injections_found;
    }

    /**
     * Get recently modified files
     *
     * @since    1.0.52
     * @return   array    Array of recently modified files
     */
    private function get_recently_modified_files()
    {
        $recent_files = array();
        $cutoff_time = time() - (15 * MINUTE_IN_SECONDS); // Last 15 minutes

        $directories = array(
            ABSPATH,
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/plugins'
        );

        foreach ($directories as $dir) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getMTime() > $cutoff_time) {
                    $recent_files[] = $file->getPathname();
                }
            }
        }

        return $recent_files;
    }

    /**
     * Check if file modification is suspicious
     *
     * @since    1.0.52
     * @param    string    $file_path    Path to the file
     * @return   boolean   True if suspicious
     */
    private function is_suspicious_modification($file_path)
    {
        // Check if it's a core WordPress file
        if ($this->is_wordpress_core_file($file_path)) {
            return true;
        }

        // Check if it's a hidden file
        $filename = basename($file_path);
        if ($filename[0] === '.') {
            return true;
        }

        // Check if it's in uploads directory
        $upload_dir = wp_upload_dir();
        if (strpos($file_path, $upload_dir['basedir']) === 0 && pathinfo($file_path, PATHINFO_EXTENSION) === 'php') {
            return true;
        }

        return false;
    }

    /**
     * Handle suspicious file changes
     *
     * @since    1.0.52
     * @param    string    $file_path    Path to the suspicious file
     */
    private function handle_suspicious_file_change($file_path)
    {
        // Quarantine the file immediately
        $fixer = new Themewire_Security_Fixer();
        $quarantine_result = $fixer->quarantine_file(0, $file_path);

        // Log the incident
        $this->logger->warning('Suspicious file modification detected', array(
            'file' => $file_path,
            'action' => 'quarantined',
            'time' => current_time('mysql')
        ));

        // Send immediate alert
        $this->send_security_alert('File Tampering Detected', array(
            'file' => $file_path,
            'action' => 'Real-time quarantine applied',
            'time' => current_time('mysql')
        ));
    }

    /**
     * Get client IP address
     *
     * @since    1.0.52
     * @return   string    Client IP address
     */
    private function get_client_ip()
    {
        $ip_headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        );

        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = trim(explode(',', $_SERVER[$header])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Check if IP is malicious
     *
     * @since    1.0.52
     * @param    string    $ip    IP address to check
     * @return   boolean   True if malicious
     */
    private function is_malicious_ip($ip)
    {
        // Check local blacklist first
        $blocked_ips = get_option('twss_blocked_ips', array());
        if (in_array($ip, $blocked_ips)) {
            return true;
        }

        // Check against threat intelligence feeds (implement API calls)
        $threat_feeds = array(
            'https://api.abuseipdb.com/api/v2/check',
            'https://api.virustotal.com/vtapi/v2/ip-address/report'
        );

        // For now, implement basic heuristics
        if ($this->is_tor_exit_node($ip) || $this->is_known_botnet_ip($ip)) {
            return true;
        }

        return false;
    }

    /**
     * Check if password meets strength requirements
     *
     * @since    1.0.52
     * @param    string    $password    Password to check
     * @return   boolean   True if strong
     */
    private function is_strong_password($password)
    {
        // Minimum 12 characters
        if (strlen($password) < 12) {
            return false;
        }

        // Must contain uppercase, lowercase, number, and special character
        if (
            !preg_match('/[A-Z]/', $password) ||
            !preg_match('/[a-z]/', $password) ||
            !preg_match('/[0-9]/', $password) ||
            !preg_match('/[^A-Za-z0-9]/', $password)
        ) {
            return false;
        }

        return true;
    }

    /**
     * Send security alert
     *
     * @since    1.0.52
     * @param    string    $subject    Alert subject
     * @param    array     $details    Alert details
     */
    private function send_security_alert($subject, $details)
    {
        if (!get_option('twss_real_time_alerts', false)) {
            return;
        }

        $to = get_option('twss_notification_email', get_option('admin_email'));
        $message = "SECURITY ALERT: {$subject}\n\n";

        foreach ($details as $key => $value) {
            $message .= ucfirst($key) . ": {$value}\n";
        }

        $message .= "\nTimestamp: " . current_time('mysql');
        $message .= "\nServer: " . $_SERVER['HTTP_HOST'];

        wp_mail($to, "[Themewire Security] {$subject}", $message);
    }

    /**
     * Detect process anomalies
     *
     * @since    1.0.52
     */
    private function detect_process_anomalies()
    {
        // Monitor for suspicious process patterns
        $suspicious_patterns = array(
            'eval(',
            'exec(',
            'system(',
            'shell_exec(',
            'passthru(',
            'file_get_contents(',
            'file_put_contents(',
            'fopen(',
            'fwrite(',
            'base64_decode(',
            'str_rot13(',
            'gzinflate(',
            'gzuncompress(',
        );

        // Get current execution context
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10);

        foreach ($backtrace as $trace) {
            if (isset($trace['function'])) {
                if (in_array($trace['function'] . '(', $suspicious_patterns)) {
                    $this->log_suspicious_activity('process_anomaly', array(
                        'function' => $trace['function'],
                        'file' => isset($trace['file']) ? $trace['file'] : 'unknown',
                        'line' => isset($trace['line']) ? $trace['line'] : 'unknown'
                    ));
                }
            }
        }
    }

    /**
     * Detect file write anomalies
     *
     * @since    1.0.52
     */
    private function detect_file_write_anomalies()
    {
        // Monitor recently created/modified files
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];

        if (!is_dir($uploads_path)) {
            return;
        }

        $recent_files = array();
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploads_path));

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getMTime() > (time() - 300)) { // 5 minutes
                $recent_files[] = $file->getPathname();
            }
        }

        foreach ($recent_files as $file) {
            if ($this->is_suspicious_file($file)) {
                $this->quarantine_suspicious_file($file, 'Recent suspicious file creation');
            }
        }
    }

    /**
     * Detect mass file changes
     *
     * @since    1.0.52
     */
    private function detect_mass_file_changes()
    {
        $recent_changes = get_transient('twss_recent_file_changes') ?: array();

        // If more than 50 files changed in 5 minutes, flag as suspicious
        if (count($recent_changes) > 50) {
            $this->send_security_alert('Mass File Modification Detected', array(
                'files_changed' => count($recent_changes),
                'timeframe' => '5 minutes',
                'user_ip' => $this->get_client_ip()
            ));
        }
    }

    /**
     * Block IP temporarily
     *
     * @since    1.0.52
     * @param    string    $ip      IP to block
     * @param    string    $reason  Reason for blocking
     */
    private function block_ip_temporarily($ip, $reason)
    {
        $blocked_ips = get_option('twss_blocked_ips_temp', array());
        $blocked_ips[$ip] = array(
            'reason' => $reason,
            'timestamp' => time(),
            'expires' => time() + (24 * HOUR_IN_SECONDS) // 24 hours
        );

        update_option('twss_blocked_ips_temp', $blocked_ips);

        $this->logger->log('security', "Temporarily blocked IP: {$ip} - Reason: {$reason}");
    }

    /**
     * Block IP permanently
     *
     * @since    1.0.52
     * @param    string    $ip      IP to block
     * @param    string    $reason  Reason for blocking
     */
    private function block_ip_permanently($ip, $reason)
    {
        $blocked_ips = get_option('twss_blocked_ips_permanent', array());
        $blocked_ips[$ip] = array(
            'reason' => $reason,
            'timestamp' => time()
        );

        update_option('twss_blocked_ips_permanent', $blocked_ips);

        $this->logger->log('security', "Permanently blocked IP: {$ip} - Reason: {$reason}");
    }

    /**
     * Check if IP is from blocked country
     *
     * @since    1.0.52
     * @param    string    $ip    IP address
     * @return   bool      True if blocked
     */
    private function is_blocked_country($ip)
    {
        $blocked_countries = get_option('twss_blocked_countries', array());

        if (empty($blocked_countries)) {
            return false;
        }

        // Simple country detection (in production, use proper GeoIP service)
        $country = $this->get_country_by_ip($ip);

        return in_array($country, $blocked_countries);
    }

    /**
     * Get country by IP (simplified)
     *
     * @since    1.0.52
     * @param    string    $ip    IP address
     * @return   string    Country code
     */
    private function get_country_by_ip($ip)
    {
        // In production, integrate with proper GeoIP service
        // This is a placeholder implementation
        return 'US';
    }

    /**
     * Log blocked access
     *
     * @since    1.0.52
     * @param    string    $ip      IP address
     * @param    string    $reason  Block reason
     */
    private function log_blocked_access($ip, $reason)
    {
        $this->logger->log('security', "Blocked access from {$ip}: {$reason}");
    }

    /**
     * Handle SQL injection attempt
     *
     * @since    1.0.52
     * @param    string    $query    Suspicious query
     */
    private function handle_sql_injection_attempt($query)
    {
        $ip = $this->get_client_ip();

        // Log the attempt
        $this->logger->log('security', "SQL injection attempt from {$ip}: " . substr($query, 0, 200));

        // Block IP temporarily
        $this->block_ip_temporarily($ip, 'SQL injection attempt');

        // Send alert
        $this->send_security_alert('SQL Injection Attempt', array(
            'ip' => $ip,
            'query_preview' => substr($query, 0, 100),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown'
        ));

        // Die execution
        if (function_exists('wp_die')) {
            wp_die(__('Security violation detected.', 'themewire-security'));
        } else {
            die('Security violation detected.');
        }
    }

    /**
     * Block malicious request
     *
     * @since    1.0.52
     * @param    string    $pattern    Matched pattern
     * @param    string    $input      Input that matched
     */
    private function block_malicious_request($pattern, $input)
    {
        $ip = $this->get_client_ip();

        // Log the attempt
        $this->logger->log('security', "Malicious request blocked from {$ip}: Pattern '{$pattern}' matched");

        // Block IP temporarily
        $this->block_ip_temporarily($ip, "Malicious pattern: {$pattern}");

        // Send alert
        $this->send_security_alert('Malicious Request Blocked', array(
            'ip' => $ip,
            'pattern' => $pattern,
            'input_preview' => substr($input, 0, 100),
            'request_uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'Unknown'
        ));

        // Die execution
        if (function_exists('wp_die')) {
            wp_die(__('Security violation detected.', 'themewire-security'));
        } else {
            die('Security violation detected.');
        }
    }

    /**
     * Log suspicious activity
     *
     * @since    1.0.52
     * @param    string    $type       Activity type
     * @param    array     $details    Activity details
     */
    private function log_suspicious_activity($type, $details)
    {
        $this->logger->log('security', "Suspicious activity ({$type}): " . json_encode($details));

        // Store for behavioral analysis
        $suspicious_activities = get_transient('twss_suspicious_activities') ?: array();
        $suspicious_activities[] = array(
            'type' => $type,
            'details' => $details,
            'timestamp' => time(),
            'ip' => $this->get_client_ip()
        );

        // Keep only last 100 activities
        if (count($suspicious_activities) > 100) {
            $suspicious_activities = array_slice($suspicious_activities, -100);
        }

        set_transient('twss_suspicious_activities', $suspicious_activities, HOUR_IN_SECONDS);
    }

    /**
     * Check if file is suspicious
     *
     * @since    1.0.52
     * @param    string    $file    File path
     * @return   bool      True if suspicious
     */
    private function is_suspicious_file($file)
    {
        // Check file extension
        $suspicious_extensions = array('.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp');
        $file_ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));

        if (in_array('.' . $file_ext, $suspicious_extensions)) {
            return true;
        }

        // Check file content for suspicious patterns
        if (is_readable($file) && filesize($file) < 1048576) { // 1MB limit
            $content = file_get_contents($file);
            $suspicious_patterns = array(
                'eval(',
                'base64_decode(',
                'file_get_contents(',
                'shell_exec(',
                'system(',
                'exec(',
                'passthru('
            );

            foreach ($suspicious_patterns as $pattern) {
                if (strpos($content, $pattern) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Quarantine suspicious file
     *
     * @since    1.0.52
     * @param    string    $file      File path
     * @param    string    $reason    Quarantine reason
     */
    private function quarantine_suspicious_file($file, $reason)
    {
        if (!is_readable($file)) {
            return;
        }

        $quarantine_dir = WP_CONTENT_DIR . '/twss-quarantine/';
        if (!is_dir($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
        }

        $quarantine_file = $quarantine_dir . basename($file) . '_' . time();

        if (copy($file, $quarantine_file)) {
            unlink($file);

            $this->logger->log('security', "Quarantined suspicious file: {$file} -> {$quarantine_file} (Reason: {$reason})");

            $this->send_security_alert('Suspicious File Quarantined', array(
                'original_file' => $file,
                'quarantine_file' => $quarantine_file,
                'reason' => $reason
            ));
        }
    }
}
