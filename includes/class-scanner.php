<?php

/**
 * The Security-Hardened Scanner functionality of the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 * @last-modified 2025-07-14 23:35:07
 * @modified-by Security Team
 * @security   Enhanced with comprehensive input validation and path traversal protection
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Scanner
{
    /**
     * The AI analyzer instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_AI_Analyzer    $ai_analyzer
     */
    private $ai_analyzer;

    /**
     * The database handler instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Database    $database
     */
    private $database;

    /**
     * The fixer instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Fixer    $fixer
     */
    private $fixer;

    /**
     * Logger instance.
     *
     * @since    1.0.2
     * @access   private
     * @var      Themewire_Security_Logger    $logger
     */
    private $logger;

    /**
     * Rate limiter instance.
     *
     * @since    1.0.2
     * @access   private
     * @var      Themewire_Security_Rate_Limiter    $rate_limiter
     */
    private $rate_limiter;

    /**
     * Scan in progress flag
     *
     * @since    1.0.0
     * @access   private
     * @var      boolean    $scan_in_progress
     */
    private $scan_in_progress = false;

    /**
     * Scan batch size for chunking large scans - dynamically adjusted
     * 
     * @since    1.0.27
     * @access   private
     * @var      int    $batch_size
     */
    private $batch_size = 50;

    /**
     * Maximum execution time per chunk in seconds
     * 
     * @since    1.0.27
     * @access   private
     * @var      int    $chunk_time_limit
     */
    private $chunk_time_limit = 25;

    /**
     * Scan priorities configuration
     * 
     * @since    1.0.27
     * @access   private
     * @var      array    $scan_priorities
     */
    private $scan_priorities = array(
        'critical' => array(
            'uploads' => 1,        // PHP files in uploads - highest priority
            'suspicious_files' => 2, // Hidden files, suspicious names
            'backdoors' => 3       // Known backdoor patterns
        ),
        'high' => array(
            'core_modified' => 4,  // Modified core files
            'active_plugins' => 5, // Currently active plugins
            'wp_config' => 6       // WordPress configuration files
        ),
        'medium' => array(
            'inactive_plugins' => 7, // Inactive plugins
            'active_themes' => 8,    // Active theme files
            'mu_plugins' => 9        // Must-use plugins
        ),
        'low' => array(
            'inactive_themes' => 10, // Inactive themes
            'cache_files' => 11,     // Cache and temp files
            'logs' => 12            // Log files
        )
    );

    /**
     * File extensions to prioritize for scanning
     * 
     * @since    1.0.27
     * @access   private
     * @var      array    $priority_extensions
     */
    private $priority_extensions = array(
        'php',
        'js',
        'html',
        'htm',
        'phtml',
        'php3',
        'php4',
        'php5',
        'php7',
        'php8'
    );

    /**
     * File extensions to skip (safe files)
     * 
     * @since    1.0.27
     * @access   private
     * @var      array    $skip_extensions
     */
    private $skip_extensions = array(
        'jpg',
        'jpeg',
        'png',
        'gif',
        'webp',
        'svg',
        'ico',
        'pdf',
        'doc',
        'docx',
        'xls',
        'xlsx',
        'ppt',
        'pptx',
        'zip',
        'rar',
        '7z',
        'tar',
        'gz',
        'mp3',
        'mp4',
        'wav',
        'avi',
        'mov',
        'css',
        'sass',
        'scss',
        'less',
        'woff',
        'woff2',
        'ttf',
        'eot'
    );

    /**
     * Server performance metrics
     * 
     * @since    1.0.27
     * @access   private
     * @var      array    $performance_metrics
     */
    private $performance_metrics = array(
        'memory_limit' => 0,
        'execution_time' => 0,
        'load_average' => 0,
        'performance_class' => 'medium' // low, medium, high
    );

    /**
     * Initialize the scanner with enhanced security validation.
     *
     * @since    1.0.0
     * @security Enhanced constructor with capability and input validation
     */
    public function __construct()
    {
        // Initialize components with error handling (no capability checks in constructor)
        try {
            $this->ai_analyzer = new Themewire_Security_AI_Analyzer();
            $this->database = new Themewire_Security_Database();
            $this->fixer = new Themewire_Security_Fixer();

            // Initialize logger and rate limiter if classes exist
            if (class_exists('Themewire_Security_Logger')) {
                $this->logger = new Themewire_Security_Logger();
            }

            if (class_exists('Themewire_Security_Rate_Limiter')) {
                $this->rate_limiter = new Themewire_Security_Rate_Limiter();
            }

            // Initialize intelligent scanning system with security validation
            $this->initialize_intelligent_scanning();

            // Try to increase PHP time limit for long-running scans (only if WordPress is loaded)
            if (function_exists('wp_get_current_user')) {
                $this->safely_increase_execution_time();
            }

            // Initialize performance monitoring
            $this->initialize_performance_monitoring();
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error('Scanner initialization failed: ' . $e->getMessage());
            }
            error_log('TWSS Scanner initialization failed: ' . $e->getMessage());
        }
    }

    /**
     * Validate user permissions for security operations.
     *
     * @since    1.0.32
     * @return   bool    True if user has required permissions
     */
    public function validate_user_permissions()
    {
        // Only check permissions when WordPress is fully loaded
        if (!function_exists('current_user_can')) {
            return false;
        }

        return current_user_can('manage_options');
    }

    /**
     * Standalone emergency scanner that works without database connection.
     * This method can detect malware even when WordPress database is unavailable.
     *
     * @since    1.0.33
     * @param    string    $wordpress_root    Path to WordPress root directory
     * @return   array     Scan results with detected threats
     */
    public function emergency_standalone_scan($wordpress_root = null)
    {
        if ($wordpress_root === null) {
            $wordpress_root = realpath(dirname(dirname(dirname(__DIR__))));
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
                $this->emergency_scan_directory($directory, $wordpress_root, $results);
            }
        }

        // Generate summary
        $results['summary']['total_threats'] = $results['threats_found'];
        $results['status'] = $results['threats_found'] > 0 ? 'THREATS_DETECTED' : 'CLEAN';

        return $results;
    }

    /**
     * Emergency scan a directory recursively.
     *
     * @since    1.0.33
     * @param    string    $directory        Directory to scan
     * @param    string    $wordpress_root   WordPress root path
     * @param    array     &$results         Results array to update
     */
    private function emergency_scan_directory($directory, $wordpress_root, &$results)
    {
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
                    $threat_level = $this->emergency_check_file_for_malware($filepath, $wordpress_root);

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
                    }
                }
            }
        }
    }

    /**
     * Property to store last detected patterns for reporting.
     *
     * @since    1.0.33
     * @access   private
     * @var      array    $last_detected_patterns
     */
    private $last_detected_patterns = array();

    /**
     * Emergency malware detection without database dependency.
     *
     * @since    1.0.33
     * @param    string    $filepath    Path to file to check
     * @param    string    $wp_root     WordPress root path
     * @return   int       Threat score (0-100)
     */
    private function emergency_check_file_for_malware($filepath, $wp_root)
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

        // Enhanced malware patterns
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
            '\$_GET\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(' => 75
        );

        // Check each pattern
        foreach ($malware_patterns as $pattern => $score) {
            if (preg_match('/' . $pattern . '/i', $content)) {
                $threat_score += $score;
                $this->last_detected_patterns[] = $pattern;
            }
        }

        // Heuristic checks
        $chr_count = preg_match_all('/chr\(\d+\)/', $content);
        if ($chr_count > 20) {
            $threat_score += 50;
            $this->last_detected_patterns[] = "Heavy chr() obfuscation ($chr_count instances)";
        }

        // Check for XOR operations (encryption)
        if (preg_match('/\^\s*\$/', $content)) {
            $threat_score += 25;
            $this->last_detected_patterns[] = "XOR operations detected";
        }

        // Variable function calls
        if (preg_match('/\$\w+\s*\(\s*\$/', $content)) {
            $threat_score += 30;
            $this->last_detected_patterns[] = "Variable function calls";
        }

        // Suspicious file locations
        $relative_path = str_replace($wp_root, '', $filepath);
        if (strpos($relative_path, '/wp-content/uploads/') !== false && pathinfo($filepath, PATHINFO_EXTENSION) === 'php') {
            $threat_score += 60;
            $this->last_detected_patterns[] = "PHP file in uploads directory";
        }

        // Cap the score at 100
        return min($threat_score, 100);
    }

    /**
     * Security-enhanced path validation to prevent path traversal attacks.
     *
     * @since    1.0.32
     * @param    string    $path    Path to validate
     * @param    string    $base_path    Base path to restrict to (optional)
     * @return   string|false    Validated path or false if invalid
     */
    private function validate_and_secure_path($path, $base_path = null)
    {
        if (empty($path) || !is_string($path)) {
            return false;
        }

        // Security: Remove null bytes and normalize path separators
        $path = str_replace(array("\0", "\\"), array('', '/'), $path);

        // Security: Resolve real path to prevent path traversal
        $real_path = realpath($path);
        if ($real_path === false) {
            return false;
        }

        // Security: Ensure path is within WordPress installation
        $wp_root = realpath(ABSPATH);
        if ($wp_root === false || strpos($real_path, $wp_root) !== 0) {
            if ($this->logger) {
                $this->logger->warning("Path traversal attempt blocked: {$path}");
            }
            return false;
        }

        // Security: Additional base path validation if provided
        if ($base_path !== null) {
            $real_base = realpath($base_path);
            if ($real_base === false || strpos($real_path, $real_base) !== 0) {
                return false;
            }
        }

        return $real_path;
    }

    /**
     * Safely increase execution time with proper validation.
     *
     * @since    1.0.32
     * @security Enhanced with proper validation and logging
     */
    private function safely_increase_execution_time()
    {
        // Security: Only increase if running in CLI or admin context
        if (!(defined('WP_CLI') && WP_CLI) && function_exists('is_admin') && !is_admin()) {
            return;
        }

        // Security: Validate current user capabilities only if WordPress is fully loaded
        if (!$this->validate_user_permissions()) {
            return;
        }

        $current_limit = ini_get('max_execution_time');
        $desired_limit = 300; // 5 minutes maximum

        // Security: Only increase if current limit is lower and not unlimited (0)
        if ($current_limit !== '0' && ($current_limit === false || (int)$current_limit < $desired_limit)) {
            $result = @ini_set('max_execution_time', $desired_limit);

            if ($this->logger) {
                if ($result !== false) {
                    $this->logger->info("Execution time limit increased to {$desired_limit} seconds");
                } else {
                    $this->logger->warning("Failed to increase execution time limit");
                }
            }
        }
    }

    /**
     * Initialize performance monitoring with security checks.
     *
     * @since    1.0.32
     * @security Enhanced with input validation
     */
    private function initialize_performance_monitoring()
    {
        try {
            // Security: Safely get memory limit
            $memory_limit = ini_get('memory_limit');
            if ($memory_limit !== false) {
                $this->performance_metrics['memory_limit'] = $this->parse_memory_limit($memory_limit);
            }

            // Security: Safely get execution time
            $execution_time = ini_get('max_execution_time');
            if ($execution_time !== false) {
                $this->performance_metrics['execution_time'] = max(0, (int)$execution_time);
            }

            // Security: Safely check server load (Unix systems only)
            if (function_exists('sys_getloadavg') && is_callable('sys_getloadavg')) {
                $load = sys_getloadavg();
                if (is_array($load) && isset($load[0]) && is_numeric($load[0])) {
                    $this->performance_metrics['load_average'] = $load[0];
                }
            }

            // Determine performance class based on metrics
            $this->classify_performance();
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->warning('Performance monitoring initialization failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * Parse memory limit string securely.
     *
     * @since    1.0.32
     * @param    string    $memory_limit    Memory limit string (e.g., "128M", "1G")
     * @return   int       Memory limit in bytes
     */
    private function parse_memory_limit($memory_limit)
    {
        if (!is_string($memory_limit)) {
            return 0;
        }

        $memory_limit = trim(strtoupper($memory_limit));
        $bytes = 0;

        // Extract numeric part
        if (preg_match('/^(\d+)([KMGT]?)$/', $memory_limit, $matches)) {
            $value = (int)$matches[1];
            $unit = isset($matches[2]) ? $matches[2] : '';

            switch ($unit) {
                case 'G':
                    $bytes = $value * 1024 * 1024 * 1024;
                    break;
                case 'M':
                    $bytes = $value * 1024 * 1024;
                    break;
                case 'K':
                    $bytes = $value * 1024;
                    break;
                default:
                    $bytes = $value;
            }
        }

        return max(0, $bytes);
    }

    /**
     * Classify server performance based on available resources.
     *
     * @since    1.0.32
     * @security Enhanced with proper validation
     */
    private function classify_performance()
    {
        $memory_mb = $this->performance_metrics['memory_limit'] / (1024 * 1024);
        $execution_time = $this->performance_metrics['execution_time'];
        $load_avg = $this->performance_metrics['load_average'];

        // Default to medium performance
        $performance_class = 'medium';

        // High performance server indicators
        if ($memory_mb >= 256 && $execution_time >= 60 && $load_avg <= 1.0) {
            $performance_class = 'high';
            $this->batch_size = 100;
            $this->chunk_time_limit = 40;
        }
        // Low performance server indicators  
        elseif ($memory_mb < 128 || $execution_time <= 30 || $load_avg > 2.0) {
            $performance_class = 'low';
            $this->batch_size = 25;
            $this->chunk_time_limit = 15;
        }
        // Medium performance (default)
        else {
            $this->batch_size = 50;
            $this->chunk_time_limit = 25;
        }

        $this->performance_metrics['performance_class'] = $performance_class;

        if ($this->logger) {
            $this->logger->info("Server classified as {$performance_class} performance (Memory: {$memory_mb}MB, Time: {$execution_time}s, Load: {$load_avg})");
        }
    }

    /**
     * Start optimized progressive scan with real-time updates
     *
     * @since    1.0.29
     * @return   array    Scan initialization result
     */
    public function start_optimized_scan()
    {
        // Security: Validate user permissions if WordPress is loaded
        if (!$this->validate_user_permissions()) {
            throw new Exception('Insufficient permissions to start security scan.');
        }
        // Check if scan already running
        if ($this->is_scan_in_progress()) {
            $last_activity = get_transient('twss_scan_last_activity');
            if ($last_activity && (time() - $last_activity) > 3600) {
                // Reset stuck scan
                $this->reset_scan_state();
                delete_option('twss_current_scan_id'); // Clear stuck scan ID
                if ($this->logger) {
                    $this->logger->warning('Detected stuck scan, resetting scan status');
                }
            } else {
                return array(
                    'success' => false,
                    'message' => __('A scan is already in progress', 'themewire-security')
                );
            }
        }

        // Clear any existing scan ID when starting fresh scan
        delete_option('twss_current_scan_id');

        if ($this->logger) {
            $this->logger->info('Starting optimized progressive security scan');
        }

        // Set scan in progress
        $this->set_scan_in_progress(true);
        $this->update_scan_activity();

        // Clean up ghost issues
        $ghost_count = $this->database->cleanup_ghost_issues();
        if ($ghost_count > 0 && $this->logger) {
            $this->logger->info("Cleaned up {$ghost_count} ghost issues before starting scan");
        }

        $scan_id = $this->database->create_new_scan_record();

        // Pre-calculate total files for accurate progress tracking
        $file_inventory = $this->calculate_scan_inventory();

        // Initialize optimized scan state
        $scan_state = array(
            'scan_id' => $scan_id,
            'stage' => 'critical_files',
            'stage_progress' => 0,
            'files_scanned' => 0,
            'total_files' => $file_inventory['total_files'],
            'stage_totals' => $file_inventory['stage_totals'],
            'current_directory' => '',
            'started' => time(),
            'last_update' => time()
        );

        // Store scan state
        set_transient('twss_optimized_scan_state', $scan_state, DAY_IN_SECONDS);
        update_option('twss_current_scan_id', $scan_id);

        // Update initial progress with file counts
        $this->database->update_scan_progress(
            $scan_id,
            'initializing',
            0,
            sprintf(__('Scan initialized: %d total files found', 'themewire-security'), $file_inventory['total_files'])
        );

        // Process the first chunk immediately to get scan started
        $first_chunk_result = $this->process_optimized_scan_chunk();

        return array(
            'success' => true,
            'scan_id' => $scan_id,
            'total_files' => $file_inventory['total_files'],
            'stage_breakdown' => $file_inventory['stage_totals'],
            'optimized' => true,
            'first_chunk_processed' => $first_chunk_result['success'],
            'message' => sprintf(__('Optimized scan initialized: %d files queued for scanning', 'themewire-security'), $file_inventory['total_files'])
        );
    }

    /**
     * Calculate comprehensive file inventory for progress tracking
     *
     * @since    1.0.29
     * @return   array    File inventory with totals and breakdown
     */
    private function calculate_scan_inventory()
    {
        $inventory = array(
            'total_files' => 0,
            'stage_totals' => array(
                'critical_files' => 0,
                'core_files' => 0,
                'plugins' => 0,
                'themes' => 0,
                'uploads' => 0
            ),
            'directories' => array()
        );

        // 1. Critical files (uploads PHP, suspicious files)
        $critical_files = $this->find_critical_files();
        $inventory['stage_totals']['critical_files'] = count($critical_files);
        $inventory['total_files'] += count($critical_files);
        $this->logger->info("File inventory: Found " . count($critical_files) . " critical files");

        // 2. ALL Core files (comprehensive scan, not just samples)
        $core_files = $this->find_all_core_files();
        $inventory['stage_totals']['core_files'] = count($core_files);
        $inventory['total_files'] += count($core_files);
        $this->logger->info("File inventory: Found " . count($core_files) . " core files");

        // 3. ALL plugins (active AND inactive for security)
        $plugin_files = $this->find_all_plugin_files();
        $inventory['stage_totals']['plugins'] = count($plugin_files);
        $inventory['total_files'] += count($plugin_files);
        $this->logger->info("File inventory: Found " . count($plugin_files) . " plugin files");

        // 4. ALL themes (active AND inactive for security)
        $theme_files = $this->find_all_theme_files();
        $inventory['stage_totals']['themes'] = count($theme_files);
        $inventory['total_files'] += count($theme_files);
        $this->logger->info("File inventory: Found " . count($theme_files) . " theme files");

        // 5. All uploads directory files (comprehensive security scan)
        $upload_files = $this->find_all_upload_files();
        $inventory['stage_totals']['uploads'] = count($upload_files);
        $inventory['total_files'] += count($upload_files);

        $this->logger->info('Comprehensive scan inventory calculated', array(
            'total_files' => $inventory['total_files'],
            'critical_files' => $inventory['stage_totals']['critical_files'],
            'core_files' => $inventory['stage_totals']['core_files'],
            'plugins' => $inventory['stage_totals']['plugins'],
            'themes' => $inventory['stage_totals']['themes'],
            'uploads' => $inventory['stage_totals']['uploads']
        ));

        return $inventory;
    }

    /**
     * Process optimized scan chunk with real-time progress
     *
     * @since    1.0.29
     * @return   array    Processing result with detailed progress
     */
    public function process_optimized_scan_chunk()
    {
        $scan_state = get_transient('twss_optimized_scan_state');
        if (!$scan_state) {
            return array(
                'success' => false,
                'message' => __('No active scan found', 'themewire-security')
            );
        }

        $this->update_scan_activity();
        $start_time = time();
        $files_processed = 0;
        $max_files_per_chunk = 15; // Smaller chunks for faster updates
        $max_time_per_chunk = 15; // 15 seconds max per chunk

        $scan_id = $scan_state['scan_id'];
        $stage = $scan_state['stage'];

        // Get files for current stage
        $files_to_scan = $this->get_files_for_stage($stage, $scan_state);

        if (empty($files_to_scan)) {
            // Check if current stage is truly complete before moving to next
            $stage_offset = isset($scan_state['stage_offset']) ? $scan_state['stage_offset'] : 0;
            $stage_total = isset($scan_state['stage_totals'][$stage]) ? $scan_state['stage_totals'][$stage] : 0;

            // Only move to next stage if we've actually scanned all files for this stage
            if ($stage_offset >= $stage_total && $stage_total > 0) {
                // Move to next stage
                $next_stage = $this->get_next_scan_stage($stage);
                if ($next_stage) {
                    $scan_state['stage'] = $next_stage;
                    $scan_state['current_directory'] = '';
                    $scan_state['stage_offset'] = 0; // Reset offset for new stage
                    set_transient('twss_optimized_scan_state', $scan_state, DAY_IN_SECONDS);

                    return array(
                        'success' => true,
                        'stage_completed' => $stage,
                        'next_stage' => $next_stage,
                        'progress' => $this->calculate_overall_progress($scan_state),
                        'continue' => true,
                        'message' => sprintf(
                            __('Completed %s scan (%d/%d files), moving to %s', 'themewire-security'),
                            ucfirst(str_replace('_', ' ', $stage)),
                            $stage_offset,
                            $stage_total,
                            ucfirst(str_replace('_', ' ', $next_stage))
                        )
                    );
                } else {
                    // All stages completed - check if we've truly scanned expected files
                    if ($scan_state['files_scanned'] >= ($scan_state['total_files'] * 0.95)) { // Allow 5% tolerance
                        return $this->finalize_optimized_scan($scan_state);
                    }
                }
            }

            // If we reach here, something's not right - continue with current stage
            // This prevents premature finalization
            return array(
                'success' => true,
                'files_processed' => 0,
                'files_scanned' => $scan_state['files_scanned'],
                'total_files' => $scan_state['total_files'],
                'overall_progress' => $this->calculate_overall_progress($scan_state),
                'current_stage' => ucfirst(str_replace('_', ' ', $stage)),
                'continue' => true,
                'message' => sprintf(
                    __('Continuing %s scan - stage offset: %d, stage total: %d', 'themewire-security'),
                    $stage,
                    $stage_offset,
                    $stage_total
                )
            );
        }

        // Process files with time and count limits
        $issues_found = 0;
        foreach ($files_to_scan as $file_info) {
            if ($files_processed >= $max_files_per_chunk || (time() - $start_time) >= $max_time_per_chunk) {
                break;
            }

            $file_path = is_array($file_info) ? $file_info['path'] : $file_info;
            $directory = dirname($file_path);

            // Update current directory for UI display
            if ($scan_state['current_directory'] !== $directory) {
                $scan_state['current_directory'] = $directory;
            }

            // Scan the file
            $scan_result = $this->scan_file_optimized($scan_id, $file_path, $stage);
            if ($scan_result && isset($scan_result['issues_found'])) {
                $issues_found += $scan_result['issues_found'];
            }

            $files_processed++;
            $scan_state['files_scanned']++;
        }

        // Update scan state with incremented offset
        $scan_state['last_update'] = time();
        $scan_state['stage_offset'] = isset($scan_state['stage_offset']) ?
            $scan_state['stage_offset'] + $files_processed : $files_processed;
        set_transient('twss_optimized_scan_state', $scan_state, DAY_IN_SECONDS);

        // Calculate progress
        $overall_progress = $this->calculate_overall_progress($scan_state);
        $stage_progress = $this->calculate_stage_progress($scan_state);

        // Update database progress
        $progress_message = sprintf(
            __('Scanning %s: %d/%d files (%d%% complete) - %s', 'themewire-security'),
            ucfirst(str_replace('_', ' ', $stage)),
            $scan_state['files_scanned'],
            $scan_state['total_files'],
            $overall_progress,
            basename($scan_state['current_directory'])
        );

        $this->database->update_scan_progress($scan_id, $stage, $stage_progress, $progress_message);

        return array(
            'success' => true,
            'files_processed' => $files_processed,
            'files_scanned' => $scan_state['files_scanned'],
            'total_files' => $scan_state['total_files'],
            'overall_progress' => $overall_progress,
            'stage_progress' => $stage_progress,
            'current_stage' => ucfirst(str_replace('_', ' ', $stage)),
            'current_directory' => $scan_state['current_directory'],
            'current_file' => isset($file_path) ? basename($file_path) : '',
            'issues_found' => $issues_found,
            'continue' => true,
            'stage_breakdown' => array(
                'critical_files' => array(
                    'name' => 'Critical Files',
                    'total' => $scan_state['stage_totals']['critical_files'],
                    'completed' => $stage === 'critical_files' ? min($scan_state['files_scanned'], $scan_state['stage_totals']['critical_files']) : ($this->stage_completed($stage, 'critical_files') ? $scan_state['stage_totals']['critical_files'] : 0)
                ),
                'core_files' => array(
                    'name' => 'WordPress Core',
                    'total' => $scan_state['stage_totals']['core_files'],
                    'completed' => $stage === 'core_files' ? min($scan_state['files_scanned'] - $scan_state['stage_totals']['critical_files'], $scan_state['stage_totals']['core_files']) : ($this->stage_completed($stage, 'core_files') ? $scan_state['stage_totals']['core_files'] : 0)
                ),
                'plugins' => array(
                    'name' => 'Active Plugins',
                    'total' => $scan_state['stage_totals']['plugins'],
                    'completed' => $stage === 'plugins' ? min($scan_state['files_scanned'] - $scan_state['stage_totals']['critical_files'] - $scan_state['stage_totals']['core_files'], $scan_state['stage_totals']['plugins']) : ($this->stage_completed($stage, 'plugins') ? $scan_state['stage_totals']['plugins'] : 0)
                ),
                'themes' => array(
                    'name' => 'Active Theme',
                    'total' => $scan_state['stage_totals']['themes'],
                    'completed' => $stage === 'themes' ? min($scan_state['files_scanned'] - $scan_state['stage_totals']['critical_files'] - $scan_state['stage_totals']['core_files'] - $scan_state['stage_totals']['plugins'], $scan_state['stage_totals']['themes']) : ($this->stage_completed($stage, 'themes') ? $scan_state['stage_totals']['themes'] : 0)
                ),
                'uploads' => array(
                    'name' => 'Uploads Directory',
                    'total' => $scan_state['stage_totals']['uploads'],
                    'completed' => $stage === 'uploads' ? min($scan_state['files_scanned'] - $scan_state['stage_totals']['critical_files'] - $scan_state['stage_totals']['core_files'] - $scan_state['stage_totals']['plugins'] - $scan_state['stage_totals']['themes'], $scan_state['stage_totals']['uploads']) : ($this->stage_completed($stage, 'uploads') ? $scan_state['stage_totals']['uploads'] : 0)
                )
            ),
            'performance' => array(
                'files_per_second' => $files_processed > 0 ? round($files_processed / max((time() - $start_time), 1), 2) : 0,
                'elapsed_time' => time() - $scan_state['started'],
                'estimated_remaining' => $this->estimate_remaining_time($scan_state, $files_processed, time() - $start_time)
            ),
            'current_stage' => $stage,
            'current_directory' => basename($scan_state['current_directory']),
            'issues_found' => $issues_found,
            'continue' => true,
            'message' => $progress_message
        );
    }

    /**
     * Initialize the intelligent scanning system
     *
     * @since    1.0.27
     */
    private function initialize_intelligent_scanning()
    {
        // Analyze server performance
        $this->analyze_server_performance();

        // Optimize batch size based on performance
        $this->optimize_batch_size();

        if ($this->logger) {
            $this->logger->info('Intelligent scanning initialized', array(
                'performance_class' => $this->performance_metrics['performance_class'],
                'optimized_batch_size' => $this->batch_size,
                'memory_limit' => $this->performance_metrics['memory_limit']
            ));
        }
    }

    /**
     * Analyze server performance metrics
     *
     * @since    1.0.27
     */
    private function analyze_server_performance()
    {
        // Get memory limit
        $memory_limit = ini_get('memory_limit');
        if ($memory_limit) {
            $memory_bytes = $this->convert_memory_to_bytes($memory_limit);
            $this->performance_metrics['memory_limit'] = $memory_bytes;
        }

        // Get max execution time
        $max_execution = ini_get('max_execution_time');
        $this->performance_metrics['execution_time'] = $max_execution;

        // Determine performance class
        if ($this->performance_metrics['memory_limit'] >= 512 * 1024 * 1024 && $max_execution >= 300) {
            $this->performance_metrics['performance_class'] = 'high';
        } elseif ($this->performance_metrics['memory_limit'] >= 256 * 1024 * 1024 && $max_execution >= 120) {
            $this->performance_metrics['performance_class'] = 'medium';
        } else {
            $this->performance_metrics['performance_class'] = 'low';
        }
    }

    /**
     * Optimize batch size based on server performance
     *
     * @since    1.0.27
     */
    private function optimize_batch_size()
    {
        switch ($this->performance_metrics['performance_class']) {
            case 'high':
                $this->batch_size = 100;
                $this->chunk_time_limit = 45;
                break;
            case 'medium':
                $this->batch_size = 50;
                $this->chunk_time_limit = 25;
                break;
            case 'low':
                $this->batch_size = 25;
                $this->chunk_time_limit = 15;
                break;
        }
    }

    /**
     * Convert memory limit string to bytes
     *
     * @since    1.0.27
     * @param    string    $memory_limit    Memory limit string (e.g., "256M")
     * @return   int       Memory limit in bytes
     */
    private function convert_memory_to_bytes($memory_limit)
    {
        $memory_limit = trim($memory_limit);
        $last_char = strtolower($memory_limit[strlen($memory_limit) - 1]);
        $number = (int) substr($memory_limit, 0, -1);

        switch ($last_char) {
            case 'g':
                return $number * 1024 * 1024 * 1024;
            case 'm':
                return $number * 1024 * 1024;
            case 'k':
                return $number * 1024;
            default:
                return (int) $memory_limit;
        }
    }

    /**
     * Smart file filtering - determine if file should be scanned
     *
     * @since    1.0.27
     * @param    string    $file_path    Path to the file
     * @return   array     Array with 'should_scan' boolean and 'priority' level
     */
    private function should_scan_file($file_path)
    {
        $file_info = pathinfo($file_path);
        $extension = isset($file_info['extension']) ? strtolower($file_info['extension']) : '';
        $filename = $file_info['basename'];
        $directory = dirname($file_path);

        // Skip files with extensions that are typically safe
        if (in_array($extension, $this->skip_extensions)) {
            return array('should_scan' => false, 'priority' => 999, 'reason' => 'Safe file type');
        }

        // High priority: PHP files in uploads directory
        if ($extension === 'php' && strpos($file_path, 'wp-content/uploads') !== false) {
            return array('should_scan' => true, 'priority' => 1, 'reason' => 'PHP in uploads - CRITICAL');
        }

        // High priority: Hidden files
        if ($filename[0] === '.' && strlen($filename) > 1) {
            return array('should_scan' => true, 'priority' => 2, 'reason' => 'Hidden file');
        }

        // High priority: Suspicious filenames
        $suspicious_patterns = array(
            '/shell\d*\.php/i',
            '/cmd\.php/i',
            '/backdoor/i',
            '/malware/i',
            '/hack/i',
            '/exploit/i',
            '/inject/i',
            '/bypass/i'
        );
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $filename)) {
                return array('should_scan' => true, 'priority' => 2, 'reason' => 'Suspicious filename');
            }
        }

        // High priority: Recently modified files (within 30 days)
        if (file_exists($file_path)) {
            $file_time = filemtime($file_path);
            $thirty_days_ago = time() - (30 * 24 * 60 * 60);
            if ($file_time > $thirty_days_ago) {
                return array('should_scan' => true, 'priority' => 3, 'reason' => 'Recently modified');
            }
        }

        // Medium priority: Core WordPress files
        if (strpos($file_path, 'wp-admin') !== false || strpos($file_path, 'wp-includes') !== false) {
            return array('should_scan' => true, 'priority' => 4, 'reason' => 'WordPress core file');
        }

        // Medium priority: Active plugin files
        if (strpos($file_path, 'wp-content/plugins') !== false && in_array($extension, $this->priority_extensions)) {
            return array('should_scan' => true, 'priority' => 5, 'reason' => 'Plugin file');
        }

        // Medium priority: Theme files
        if (strpos($file_path, 'wp-content/themes') !== false && in_array($extension, $this->priority_extensions)) {
            return array('should_scan' => true, 'priority' => 6, 'reason' => 'Theme file');
        }

        // Low priority: Other executable files
        if (in_array($extension, $this->priority_extensions)) {
            return array('should_scan' => true, 'priority' => 8, 'reason' => 'Executable file');
        }

        // Skip everything else
        return array('should_scan' => false, 'priority' => 999, 'reason' => 'Not in scan scope');
    }

    /**
     * Get prioritized file list for scanning
     *
     * @since    1.0.27
     * @param    string    $directory    Directory to scan
     * @param    int       $limit        Maximum number of files to return
     * @return   array     Prioritized array of files to scan
     */
    private function get_prioritized_files($directory, $limit = 1000)
    {
        $files_to_scan = array();

        if (!is_dir($directory)) {
            return $files_to_scan;
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $file_path = $file->getPathname();
                    $scan_decision = $this->should_scan_file($file_path);

                    if ($scan_decision['should_scan']) {
                        $files_to_scan[] = array(
                            'path' => $file_path,
                            'priority' => $scan_decision['priority'],
                            'reason' => $scan_decision['reason'],
                            'size' => $file->getSize(),
                            'modified' => $file->getMTime()
                        );
                    }
                }

                // Prevent memory exhaustion on very large sites
                if (count($files_to_scan) > $limit * 2) {
                    break;
                }
            }
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error('Error reading directory: ' . $directory, array('error' => $e->getMessage()));
            }
            return array();
        }

        // Sort by priority (lower numbers = higher priority)
        usort($files_to_scan, function ($a, $b) {
            if ($a['priority'] === $b['priority']) {
                // If same priority, prioritize recently modified files
                return $b['modified'] - $a['modified'];
            }
            return $a['priority'] - $b['priority'];
        });

        // Return only the top files within limit
        return array_slice($files_to_scan, 0, $limit);
    }

    /**
     * Enhanced chunked scanning with intelligent prioritization
     *
     * @since    1.0.27
     * @param    int       $scan_id     Scan ID
     * @param    array     $scan_state  Current scan state
     * @return   array     Processing result
     */
    private function process_intelligent_chunk($scan_id, $scan_state)
    {
        $start_time = time();
        $files_processed = 0;
        $max_files = $this->batch_size;

        // Get the current stage directory
        $scan_directory = $this->get_stage_directory($scan_state['stage']);

        if (!$scan_directory) {
            return array(
                'success' => false,
                'message' => 'Invalid scan stage: ' . $scan_state['stage']
            );
        }

        // Get prioritized files for this stage
        $prioritized_files = $this->get_prioritized_files($scan_directory, $max_files * 3);

        if (empty($prioritized_files)) {
            return array(
                'stage_complete' => true,
                'next_stage' => $this->get_next_stage($scan_state['stage']),
                'progress' => 100,
                'next_offset' => 0,
                'continue' => true,
                'message' => ucfirst($scan_state['stage']) . ' scan completed - no files found'
            );
        }

        // Process files starting from current offset
        $offset = isset($scan_state['batch_offset']) ? $scan_state['batch_offset'] : 0;
        $files_to_process = array_slice($prioritized_files, $offset, $max_files);

        foreach ($files_to_process as $file_info) {
            // Check time limit
            if ((time() - $start_time) >= $this->chunk_time_limit) {
                break;
            }

            $this->scan_single_file($scan_id, $file_info['path'], $file_info['reason']);
            $files_processed++;
        }

        // Calculate progress
        $total_files = count($prioritized_files);
        $processed_total = $offset + $files_processed;
        $progress = $total_files > 0 ? min(100, ($processed_total / $total_files) * 100) : 100;

        // Determine if stage is complete
        $stage_complete = ($processed_total >= $total_files);

        return array(
            'success' => true,
            'stage_complete' => $stage_complete,
            'next_stage' => $stage_complete ? $this->get_next_stage($scan_state['stage']) : $scan_state['stage'],
            'progress' => round($progress),
            'next_offset' => $stage_complete ? 0 : $processed_total,
            'continue' => true,
            'files_processed' => $files_processed,
            'message' => sprintf(
                '%s: %d/%d files scanned (%d%% complete)',
                ucfirst($scan_state['stage']),
                $processed_total,
                $total_files,
                round($progress)
            )
        );
    }

    /**
     * Get directory for current scan stage
     *
     * @since    1.0.27
     * @param    string    $stage    Current stage
     * @return   string    Directory path or false
     */
    private function get_stage_directory($stage)
    {
        switch ($stage) {
            case 'core':
                return ABSPATH;
            case 'plugins':
                return WP_PLUGIN_DIR;
            case 'themes':
                return get_theme_root();
            case 'uploads':
                $upload_dir = wp_upload_dir();
                return $upload_dir['basedir'];
            default:
                return false;
        }
    }

    /**
     * Get next stage in scan progression
     *
     * @since    1.0.27
     * @param    string    $current_stage    Current stage
     * @return   string    Next stage
     */
    private function get_next_stage($current_stage)
    {
        $stage_progression = array(
            'core' => 'plugins',
            'plugins' => 'themes',
            'themes' => 'uploads',
            'uploads' => 'ai_analysis',
            'ai_analysis' => 'completed'
        );

        return isset($stage_progression[$current_stage]) ? $stage_progression[$current_stage] : 'completed';
    }

    /**
     * Scan a single file and record results
     *
     * @since    1.0.27
     * @param    int       $scan_id     Scan ID
     * @param    string    $file_path   Path to file
     * @param    string    $reason      Reason for scanning
     * @return   boolean   Success status
     */
    private function scan_single_file($scan_id, $file_path, $reason)
    {
        try {
            // Read file content for comprehensive analysis
            $file_content = '';
            if (is_readable($file_path) && filesize($file_path) < 10 * 1024 * 1024) { // Limit to 10MB files
                $file_content = file_get_contents($file_path);
            }

            // Store comprehensive scan result in database
            $this->database->store_scan_result($scan_id, $file_path, $file_content, array(), $reason);

            // **ENHANCED**: Add basic corruption/malware pattern detection before AI analysis
            $pattern_issues = $this->detect_basic_file_issues($file_path, $file_content);
            if (!empty($pattern_issues)) {
                foreach ($pattern_issues as $issue) {
                    $this->database->record_issue(
                        $scan_id,
                        $file_path,
                        $issue['type'],
                        $issue['severity'],
                        $issue['description'],
                        $issue['suggested_fix'],
                        json_encode(array(
                            'detection_method' => 'pattern-based',
                            'scan_reason' => $reason,
                            'pattern_match' => $issue['pattern']
                        ))
                    );
                }
            }

            // Perform the actual file analysis
            $analysis_result = $this->ai_analyzer->analyze_file($file_path);

            // If malicious, record the issue
            if ($analysis_result['is_malware'] || (isset($analysis_result['is_malicious']) && $analysis_result['is_malicious'])) {
                $confidence = isset($analysis_result['confidence']) ? $analysis_result['confidence'] : 50;
                $explanation = isset($analysis_result['explanation']) ? $analysis_result['explanation'] : 'Malicious content detected';
                $suggested_fix = isset($analysis_result['suggested_fix']) ? $analysis_result['suggested_fix'] : 'quarantine';

                // Determine severity based on confidence and indicators
                $severity = $this->determine_severity($confidence, $reason, $file_path);

                $this->database->record_issue(
                    $scan_id,
                    $file_path,
                    'malware',
                    $severity,
                    $explanation,
                    $suggested_fix,
                    json_encode(array(
                        'confidence' => $confidence,
                        'scan_reason' => $reason,
                        'indicators' => isset($analysis_result['indicators']) ? $analysis_result['indicators'] : array()
                    ))
                );

                if ($this->logger) {
                    $this->logger->warning('Malicious file detected', array(
                        'file' => $file_path,
                        'confidence' => $confidence,
                        'reason' => $reason
                    ));
                }
            }

            return true;
        } catch (Exception $e) {
            $error_message = $e->getMessage();

            // Still store the file for analysis even if initial scan fails
            if (!empty($file_path) && is_readable($file_path)) {
                try {
                    $file_content = '';
                    if (filesize($file_path) < 10 * 1024 * 1024) { // Limit to 10MB files
                        $file_content = file_get_contents($file_path);
                    }
                    $this->database->store_scan_result($scan_id, $file_path, $file_content, array(), $reason);
                } catch (Exception $storage_error) {
                    if ($this->logger) {
                        $this->logger->error('Failed to store scan result: ' . $file_path, array(
                            'error' => $storage_error->getMessage()
                        ));
                    }
                }
            }

            // Handle AI service quota/rate limiting gracefully
            if (
                strpos($error_message, 'quota') !== false ||
                strpos($error_message, 'rate limited') !== false ||
                strpos($error_message, 'temporarily unavailable') !== false
            ) {

                if ($this->logger) {
                    $this->logger->info('AI analysis unavailable for file, using pattern detection: ' . $file_path, array(
                        'reason' => 'API quota/rate limit',
                        'fallback' => 'pattern-based analysis'
                    ));
                }

                // Try pattern-based analysis as fallback
                try {
                    // Get file content and extension for fallback analysis
                    $file_content = file_get_contents($file_path);
                    $file_extension = pathinfo($file_path, PATHINFO_EXTENSION);

                    $pattern_result = $this->ai_analyzer->analyze_with_fallback($file_path, $file_content, $file_extension);
                    if ($pattern_result && isset($pattern_result['is_malware']) && $pattern_result['is_malware']) {
                        // Record issue with pattern-based detection
                        $this->database->record_issue(
                            $scan_id,
                            $file_path,
                            'malware',
                            'medium', // Default to medium severity for pattern detection
                            $pattern_result['explanation'] ?? 'Malicious patterns detected',
                            'quarantine',
                            json_encode(array(
                                'detection_method' => 'pattern-based',
                                'scan_reason' => $reason,
                                'ai_fallback' => true
                            ))
                        );
                    }
                    return true;
                } catch (Exception $pattern_error) {
                    // Even pattern analysis failed, log and continue
                    if ($this->logger) {
                        $this->logger->error('Both AI and pattern analysis failed for file: ' . $file_path, array(
                            'ai_error' => $error_message,
                            'pattern_error' => $pattern_error->getMessage()
                        ));
                    }
                    return false;
                }
            }

            // Handle other errors
            if ($this->logger) {
                $this->logger->error('Error scanning file: ' . $file_path, array('error' => $error_message));
            }
            return false;
        }
    }

    /**
     * Determine issue severity based on various factors
     *
     * @since    1.0.27
     * @param    int       $confidence  Confidence score
     * @param    string    $reason      Scan reason
     * @param    string    $file_path   File path
     * @return   string    Severity level (high, medium, low)
     */
    private function determine_severity($confidence, $reason, $file_path)
    {
        // High severity conditions
        if (
            $confidence >= 80 ||
            strpos($reason, 'CRITICAL') !== false ||
            strpos($file_path, 'wp-content/uploads') !== false ||
            strpos($reason, 'Hidden file') !== false
        ) {
            return 'high';
        }

        // Medium severity conditions
        if (
            $confidence >= 50 ||
            strpos($reason, 'Suspicious') !== false ||
            strpos($reason, 'Recently modified') !== false
        ) {
            return 'medium';
        }

        // Default to low severity
        return 'low';
    }

    /**
     * Attempt to increase PHP execution time limit
     *
     * @since    1.0.1
     */
    private function increase_execution_time()
    {
        // Only try to increase if not in safe mode
        if (!ini_get('safe_mode')) {
            @set_time_limit(300); // Try to set to 5 minutes

            // Increase memory limit if possible
            @ini_set('memory_limit', '256M');
        }
    }

    /**
     * Start a new security scan
     *
     * @since    1.0.0
     * @return   array    Scan results
     */
    public function start_scan()
    {
        // Check if scan already running
        if ($this->is_scan_in_progress()) {
            // Check if it's an old stuck scan (more than 1 hour)
            $last_activity = get_transient('twss_scan_last_activity');
            if ($last_activity && (time() - $last_activity) > 3600) {
                // Old stuck scan, reset it
                delete_transient('twss_scan_in_progress');
                delete_transient('twss_scan_last_activity');
                delete_option('twss_current_scan_id'); // Clear stuck scan ID
                if ($this->logger) {
                    $this->logger->warning('Detected stuck scan, resetting scan status');
                }
            } else {
                return array(
                    'success' => false,
                    'message' => __('A scan is already in progress', 'themewire-security')
                );
            }
        }

        // Clear any existing scan ID when starting fresh scan
        delete_option('twss_current_scan_id');

        if ($this->logger) {
            $this->logger->info('Starting new security scan');
        }

        // Set scan in progress and record activity time
        $this->set_scan_in_progress(true);
        $this->update_scan_activity();

        // Clean up any ghost files from previous scans
        $ghost_count = $this->database->cleanup_ghost_issues();
        if ($ghost_count > 0 && $this->logger) {
            $this->logger->info("Cleaned up {$ghost_count} ghost issues before starting scan");
        }

        $scan_id = $this->database->create_new_scan_record();

        try {
            // Store scan ID in option for potential resuming
            update_option('twss_current_scan_id', $scan_id);

            // Scan WordPress core files
            $this->scan_wordpress_core_files($scan_id);
            $this->update_scan_activity();

            // Scan plugins
            $this->scan_plugins($scan_id);
            $this->update_scan_activity();

            // Scan themes
            $this->scan_themes($scan_id);
            $this->update_scan_activity();

            // Scan uploads directory
            $this->scan_uploads_directory($scan_id);
            $this->update_scan_activity();

            // Analyze results with AI
            $this->analyze_scan_results($scan_id);
            $this->update_scan_activity();

            // Update scan status
            $this->database->update_scan_status($scan_id, 'completed');
            $this->logger->info('COMPLETION DEBUG: Regular scan completed via start_scan()', array('scan_id' => $scan_id));
            if ($this->logger) {
                $this->logger->info('Scan completed successfully', array('scan_id' => $scan_id));
            }            // Get scan summary
            $summary = $this->database->get_scan_summary($scan_id);

            $this->set_scan_in_progress(false);
            delete_transient('twss_scan_last_activity');
            delete_option('twss_current_scan_id');

            return array(
                'success' => true,
                'scan_id' => $scan_id,
                'summary' => $summary
            );
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error('Scan failed', array(
                    'scan_id' => $scan_id,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ));
            }

            $this->database->update_scan_status($scan_id, 'failed', $e->getMessage());
            $this->set_scan_in_progress(false);
            delete_transient('twss_scan_last_activity');

            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Update scan activity timestamp
     *
     * @since    1.0.1
     */
    private function update_scan_activity()
    {
        set_transient('twss_scan_last_activity', time(), DAY_IN_SECONDS);
    }

    /**
     * Resume an interrupted scan
     *
     * @since    1.0.1
     * @return   array    Scan results
     */
    public function resume_scan()
    {
        $scan_id = get_option('twss_current_scan_id');

        if (!$scan_id) {
            return array(
                'success' => false,
                'message' => __('No interrupted scan found to resume', 'themewire-security')
            );
        }

        $this->set_scan_in_progress(true);
        $this->update_scan_activity();

        try {
            // Get the last completed stage
            $last_progress = $this->database->get_last_scan_progress($scan_id);
            $last_stage = $last_progress ? $last_progress['stage'] : '';

            // Resume from where we left off
            if ($last_stage === 'core' || empty($last_stage)) {
                $this->scan_wordpress_core_files($scan_id);
                $this->update_scan_activity();
            }

            if ($last_stage === 'core' || $last_stage === 'plugins' || empty($last_stage)) {
                $this->scan_plugins($scan_id);
                $this->update_scan_activity();
            }

            if ($last_stage === 'core' || $last_stage === 'plugins' || $last_stage === 'themes' || empty($last_stage)) {
                $this->scan_themes($scan_id);
                $this->update_scan_activity();
            }

            if ($last_stage === 'core' || $last_stage === 'plugins' || $last_stage === 'themes' || $last_stage === 'uploads' || empty($last_stage)) {
                $this->scan_uploads_directory($scan_id);
                $this->update_scan_activity();
            }

            if ($last_stage === 'core' || $last_stage === 'plugins' || $last_stage === 'themes' || $last_stage === 'uploads' || $last_stage === 'ai_analysis' || empty($last_stage)) {
                $this->analyze_scan_results($scan_id);
                $this->update_scan_activity();
            }

            // Update scan status
            $this->database->update_scan_status($scan_id, 'completed');

            // Get scan summary
            $summary = $this->database->get_scan_summary($scan_id);

            $this->set_scan_in_progress(false);
            delete_transient('twss_scan_last_activity');
            delete_option('twss_current_scan_id');

            return array(
                'success' => true,
                'scan_id' => $scan_id,
                'summary' => $summary,
                'resumed' => true
            );
        } catch (Exception $e) {
            $this->database->update_scan_status($scan_id, 'failed', $e->getMessage());
            $this->set_scan_in_progress(false);
            delete_transient('twss_scan_last_activity');

            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Start a new chunked security scan to prevent timeouts
     *
     * @since    1.0.23
     * @return   array    Scan initialization result
     */
    public function start_chunked_scan()
    {
        // Check if scan already running
        if ($this->is_scan_in_progress()) {
            // Check if it's an old stuck scan (more than 1 hour)
            $last_activity = get_transient('twss_scan_last_activity');
            if ($last_activity && (time() - $last_activity) > 3600) {
                // Old stuck scan, reset it
                delete_transient('twss_scan_in_progress');
                delete_transient('twss_scan_last_activity');
                delete_transient('twss_chunked_scan_state');
                delete_option('twss_current_scan_id'); // Clear stuck scan ID
                if ($this->logger) {
                    $this->logger->warning('Detected stuck scan, resetting scan status');
                }
            } else {
                return array(
                    'success' => false,
                    'message' => __('A scan is already in progress', 'themewire-security')
                );
            }
        }

        // Clear any existing scan ID when starting fresh scan
        delete_option('twss_current_scan_id');

        if ($this->logger) {
            $this->logger->info('Starting new chunked security scan');
        }

        // Set scan in progress and record activity time
        $this->set_scan_in_progress(true);
        $this->update_scan_activity();

        // Clean up any ghost files from previous scans
        $ghost_count = $this->database->cleanup_ghost_issues();
        if ($ghost_count > 0 && $this->logger) {
            $this->logger->info("Cleaned up {$ghost_count} ghost issues before starting scan");
        }

        $scan_id = $this->database->create_new_scan_record();

        // Initialize chunked scan state
        $scan_state = array(
            'scan_id' => $scan_id,
            'stage' => 'core',
            'stage_progress' => 0,
            'batch_offset' => 0,
            'total_batches' => 0,
            'started' => time()
        );

        // Store scan state for chunked processing
        set_transient('twss_chunked_scan_state', $scan_state, DAY_IN_SECONDS);
        update_option('twss_current_scan_id', $scan_id);

        // Update initial progress
        $this->database->update_scan_progress($scan_id, 'core', 0, __('Starting core file scan...', 'themewire-security'));

        // Process the first chunk immediately to prevent "stuck at initializing" issue
        $first_chunk_result = $this->process_scan_chunk();

        return array(
            'success' => true,
            'scan_id' => $scan_id,
            'chunked' => true,
            'first_chunk_processed' => $first_chunk_result['success'],
            'message' => __('Scan started and first chunk processed successfully.', 'themewire-security')
        );
    }

    /**
     * Process the next chunk of the current scan
     *
     * @since    1.0.23
     * @return   array    Chunk processing result
     */
    public function process_scan_chunk()
    {
        $scan_state = get_transient('twss_chunked_scan_state');

        if (!$scan_state) {
            return array(
                'success' => false,
                'message' => __('No active chunked scan found', 'themewire-security')
            );
        }

        $start_time = time();
        $scan_id = $scan_state['scan_id'];

        $this->update_scan_activity();

        try {
            // Use intelligent scanning for file-based stages
            if (in_array($scan_state['stage'], array('core', 'plugins', 'themes', 'uploads'))) {
                $result = $this->process_intelligent_chunk($scan_id, $scan_state);
            } else {
                // Use traditional processing for AI analysis
                switch ($scan_state['stage']) {
                    case 'ai_analysis':
                        $result = $this->process_ai_analysis_chunk($scan_id, $scan_state);
                        break;

                    case 'completed':
                    default:
                        return $this->finalize_chunked_scan($scan_id);
                }
            }

            // Update scan state
            if ($result['stage_complete']) {
                $scan_state['stage'] = $result['next_stage'];
                $scan_state['stage_progress'] = 0;
                $scan_state['batch_offset'] = 0;
            } else {
                $scan_state['stage_progress'] = $result['progress'];
                $scan_state['batch_offset'] = $result['next_offset'];
            }

            // Save updated state
            set_transient('twss_chunked_scan_state', $scan_state, DAY_IN_SECONDS);

            return array(
                'success' => true,
                'stage' => $scan_state['stage'],
                'progress' => $scan_state['stage_progress'],
                'message' => $result['message'],
                'continue' => ($scan_state['stage'] !== 'completed')
            );
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error('Chunked scan chunk processing failed', array(
                    'scan_id' => $scan_id,
                    'stage' => $scan_state['stage'],
                    'error' => $e->getMessage()
                ));
            }

            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Run a scheduled security scan
     *
     * @since    1.0.0
     */
    public function run_scheduled_scan()
    {
        // Check if scan already running
        if ($this->is_scan_in_progress()) {
            return;
        }

        $result = $this->start_scan();

        if ($result['success']) {
            // Auto-fix issues if enabled
            $auto_fix = get_option('twss_auto_fix', false);
            if ($auto_fix) {
                $this->auto_fix_issues($result['scan_id']);
            }

            // Send notification email if enabled
            $send_email = get_option('twss_send_email', false);
            if ($send_email) {
                $this->send_notification_email($result['scan_id'], $result['summary']);
            }
        }
    }

    /**
     * Scan WordPress core files with chunking to prevent timeouts
     *
     * @since    1.0.0
     * @param    int    $scan_id    The ID of the current scan
     */
    private function scan_wordpress_core_files($scan_id)
    {
        // Get WordPress core file checksums
        $checksums = $this->get_wordpress_checksums();

        if (!$checksums) {
            $this->database->update_scan_progress($scan_id, 'core', 0, __('Unable to retrieve WordPress core checksums. Skipping core files scan.', 'themewire-security'));
            $this->database->update_scan_progress($scan_id, 'core', 100, __('WordPress core scan skipped.', 'themewire-security'));
            return; // Skip this scan but continue with others
        }

        $wordpress_dir = ABSPATH;
        $files_scanned = 0;
        $issues_found = 0;
        $total_files = count($checksums);

        // Check if we have a stored checkpoint
        $checkpoint = get_transient('twss_core_scan_checkpoint_' . $scan_id);
        if ($checkpoint) {
            $files_scanned = $checkpoint['files_scanned'];
            $issues_found = $checkpoint['issues_found'];
        }

        $this->database->update_scan_progress($scan_id, 'core', 0, 'Starting WordPress core files scan');

        // Convert to array for chunking
        $checksum_keys = array_keys($checksums);
        $chunks = array_chunk($checksum_keys, $this->batch_size);

        // Calculate which chunk to start from based on files_scanned
        $chunk_start = floor($files_scanned / $this->batch_size);

        // Process chunks
        for ($i = $chunk_start; $i < count($chunks); $i++) {
            $chunk = $chunks[$i];

            foreach ($chunk as $file) {
                $file_path = $wordpress_dir . $file;
                $checksum = $checksums[$file];

                if (!file_exists($file_path)) {
                    // Missing core file
                    $this->database->add_issue(
                        $scan_id,
                        'core_file_missing',
                        $file_path,
                        __('WordPress core file is missing', 'themewire-security'),
                        'high'
                    );
                    $issues_found++;
                } else {
                    $file_checksum = md5_file($file_path);

                    if ($file_checksum !== $checksum) {
                        // Modified core file
                        $this->database->add_issue(
                            $scan_id,
                            'core_file_modified',
                            $file_path,
                            __('WordPress core file has been modified', 'themewire-security'),
                            'high'
                        );
                        $issues_found++;

                        // Queue file content for AI analysis
                        $this->ai_analyzer->queue_file_for_analysis($scan_id, $file_path);
                    }
                }

                $files_scanned++;
            }

            // Save checkpoint after each chunk
            set_transient('twss_core_scan_checkpoint_' . $scan_id, array(
                'files_scanned' => $files_scanned,
                'issues_found' => $issues_found
            ), HOUR_IN_SECONDS);

            $progress = round(($files_scanned / $total_files) * 100);
            $this->database->update_scan_progress(
                $scan_id,
                'core',
                $progress,
                sprintf(__('Scanned %d of %d core files', 'themewire-security'), $files_scanned, $total_files)
            );

            // Update scan activity timestamp
            $this->update_scan_activity();
        }

        // Scan for extra files in core directories
        $this->scan_for_extra_files($scan_id, $wordpress_dir, array_keys($checksums), 'WordPress core');

        $this->database->update_scan_progress(
            $scan_id,
            'core',
            100,
            sprintf(
                __('WordPress core scan complete. %d files scanned, %d issues found.', 'themewire-security'),
                $files_scanned,
                $issues_found
            )
        );

        // Cleanup checkpoint
        delete_transient('twss_core_scan_checkpoint_' . $scan_id);
    }

    /**
     * Scan plugin files with chunking to prevent timeouts
     *
     * @since    1.0.0
     * @param    int    $scan_id    The ID of the current scan
     */
    private function scan_plugins($scan_id)
    {
        $plugins_dir = WP_PLUGIN_DIR;

        if (!is_dir($plugins_dir)) {
            throw new Exception(__('Plugins directory not found', 'themewire-security'));
        }

        $this->database->update_scan_progress($scan_id, 'plugins', 0, 'Starting plugins scan');

        // Get list of active plugins
        $active_plugins = get_option('active_plugins', array());
        $plugins = array();

        foreach ($active_plugins as $plugin) {
            $plugin_dir = dirname($plugins_dir . '/' . $plugin);
            $plugins[] = basename($plugin_dir);
        }

        // Add network active plugins if multisite
        if (is_multisite()) {
            $network_plugins = get_site_option('active_sitewide_plugins', array());
            foreach (array_keys($network_plugins) as $plugin) {
                $plugin_dir = dirname($plugins_dir . '/' . $plugin);
                $plugins[] = basename($plugin_dir);
            }
        }

        // Remove duplicates
        $plugins = array_unique($plugins);

        // Check for checkpoint
        $checkpoint = get_transient('twss_plugins_scan_checkpoint_' . $scan_id);
        $plugins_scanned = 0;
        $issues_found = 0;
        $files_scanned = 0;
        $current_plugin_index = 0;
        $current_file_index = 0;

        if ($checkpoint) {
            $plugins_scanned = $checkpoint['plugins_scanned'];
            $issues_found = $checkpoint['issues_found'];
            $files_scanned = isset($checkpoint['files_scanned']) ? $checkpoint['files_scanned'] : 0;
            $current_plugin_index = $checkpoint['current_plugin_index'];
            $current_file_index = $checkpoint['current_file_index'];
        }

        $total_plugins = count($plugins);

        // Skip already scanned plugins
        for ($i = $current_plugin_index; $i < $total_plugins; $i++) {
            $plugin = $plugins[$i];
            $plugin_path = $plugins_dir . '/' . $plugin;

            if (is_dir($plugin_path)) {
                // Get list of files in plugin directory
                $plugin_files = $this->scan_directory_recursively($plugin_path);
                $total_files = count($plugin_files);

                // Start from the last file index if resuming
                $start_file_index = ($i === $current_plugin_index) ? $current_file_index : 0;

                // Scan each file in the plugin, in chunks
                for ($j = $start_file_index; $j < $total_files; $j += $this->batch_size) {
                    $batch_end = min($j + $this->batch_size, $total_files);

                    for ($k = $j; $k < $batch_end; $k++) {
                        $file = $plugin_files[$k];

                        // Skip non-existent or unreadable files
                        if (!file_exists($file) || !is_readable($file)) {
                            continue;
                        }

                        // Skip non-PHP files for now (can expand to JS later)
                        if (pathinfo($file, PATHINFO_EXTENSION) !== 'php') {
                            continue;
                        }

                        // First do basic malware scan
                        $scan_result = $this->scan_file_for_malware($file);

                        if ($scan_result['suspicious']) {
                            // Use the fixer's advanced validation for plugins
                            $validation = $this->fixer->validate_plugin_file($file);

                            if ($validation['is_malicious'] || $scan_result['suspicious']) {
                                $confidence_text = '';
                                if (isset($validation['confidence'])) {
                                    $confidence_text = sprintf(' (Confidence: %d%%)', $validation['confidence']);
                                }

                                $description = sprintf(__('Suspicious code found in plugin file: %s%s', 'themewire-security'), $scan_result['reason'], $confidence_text);

                                if (isset($validation['indicators']) && !empty($validation['indicators'])) {
                                    $description .= ' Indicators: ' . implode(', ', $validation['indicators']);
                                }

                                $this->database->add_issue(
                                    $scan_id,
                                    'suspicious_code',
                                    $file,
                                    $description,
                                    $validation['confidence'] >= 80 ? 'high' : ($validation['confidence'] >= 50 ? 'medium' : 'low')
                                );
                                $issues_found++;

                                // Queue file for AI analysis
                                $this->ai_analyzer->queue_file_for_analysis($scan_id, $file);
                            }
                        }

                        $files_scanned++;
                    }

                    // Save checkpoint after each batch
                    set_transient('twss_plugins_scan_checkpoint_' . $scan_id, array(
                        'plugins_scanned' => $plugins_scanned,
                        'issues_found' => $issues_found,
                        'files_scanned' => $files_scanned,
                        'current_plugin_index' => $i,
                        'current_file_index' => $batch_end
                    ), HOUR_IN_SECONDS);

                    $this->update_scan_activity();
                }
            }

            $plugins_scanned++;
            $progress = round(($plugins_scanned / $total_plugins) * 100);

            $this->database->update_scan_progress(
                $scan_id,
                'plugins',
                $progress,
                sprintf(__('Scanned %d of %d plugins', 'themewire-security'), $plugins_scanned, $total_plugins)
            );

            // Save checkpoint after each plugin
            set_transient('twss_plugins_scan_checkpoint_' . $scan_id, array(
                'plugins_scanned' => $plugins_scanned,
                'issues_found' => $issues_found,
                'files_scanned' => $files_scanned,
                'current_plugin_index' => $i + 1,
                'current_file_index' => 0
            ), HOUR_IN_SECONDS);

            $this->update_scan_activity();
        }

        $this->database->update_scan_progress(
            $scan_id,
            'plugins',
            100,
            sprintf(__('Plugin scan complete. %d issues found.', 'themewire-security'), $issues_found)
        );

        // Cleanup checkpoint
        delete_transient('twss_plugins_scan_checkpoint_' . $scan_id);
    }

    /**
     * Scan theme files with chunking to prevent timeouts
     *
     * @since    1.0.0
     * @param    int    $scan_id    The ID of the current scan
     */
    private function scan_themes($scan_id)
    {
        $themes_dir = get_theme_root();

        if (!is_dir($themes_dir)) {
            throw new Exception(__('Themes directory not found', 'themewire-security'));
        }

        $this->database->update_scan_progress($scan_id, 'themes', 0, 'Starting themes scan');

        // Get list of active themes
        $active_theme = wp_get_theme();
        $themes = array($active_theme->get_stylesheet());

        // Add parent theme if child theme is active
        if ($active_theme->parent()) {
            $themes[] = $active_theme->get_template();
        }

        // Check for checkpoint
        $checkpoint = get_transient('twss_themes_scan_checkpoint_' . $scan_id);
        $themes_scanned = 0;
        $issues_found = 0;
        $current_theme_index = 0;
        $current_file_index = 0;

        if ($checkpoint) {
            $themes_scanned = $checkpoint['themes_scanned'];
            $issues_found = $checkpoint['issues_found'];
            $current_theme_index = $checkpoint['current_theme_index'];
            $current_file_index = $checkpoint['current_file_index'];
        }

        $total_themes = count($themes);

        // Skip already scanned themes
        for ($i = $current_theme_index; $i < $total_themes; $i++) {
            $theme = $themes[$i];
            $theme_path = $themes_dir . '/' . $theme;

            if (is_dir($theme_path)) {
                // Get list of files in theme directory
                $theme_files = $this->scan_directory_recursively($theme_path);
                $total_files = count($theme_files);

                // Start from the last file index if resuming
                $start_file_index = ($i === $current_theme_index) ? $current_file_index : 0;

                // Scan each file in the theme, in chunks
                for ($j = $start_file_index; $j < $total_files; $j += $this->batch_size) {
                    $batch_end = min($j + $this->batch_size, $total_files);

                    for ($k = $j; $k < $batch_end; $k++) {
                        $file = $theme_files[$k];

                        // Skip non-existent or unreadable files
                        if (!file_exists($file) || !is_readable($file)) {
                            continue;
                        }

                        // Focus on PHP files first
                        if (pathinfo($file, PATHINFO_EXTENSION) === 'php') {
                            // Scan file for common malware patterns
                            $scan_result = $this->scan_file_for_malware($file);

                            if ($scan_result['suspicious']) {
                                // Use advanced validation for themes
                                $validation = $this->fixer->advanced_malware_analysis($file);

                                $confidence_text = '';
                                if (isset($validation['confidence'])) {
                                    $confidence_text = sprintf(' (Confidence: %d%%)', $validation['confidence']);
                                }

                                $description = sprintf(__('Suspicious code found in theme file: %s%s', 'themewire-security'), $scan_result['reason'], $confidence_text);

                                if (isset($validation['indicators']) && !empty($validation['indicators'])) {
                                    $description .= ' Indicators: ' . implode(', ', $validation['indicators']);
                                }

                                $this->database->add_issue(
                                    $scan_id,
                                    'suspicious_code',
                                    $file,
                                    $description,
                                    $validation['confidence'] >= 80 ? 'high' : ($validation['confidence'] >= 50 ? 'medium' : 'low')
                                );
                                $issues_found++;

                                // Queue file for AI analysis
                                $this->ai_analyzer->queue_file_for_analysis($scan_id, $file);
                            }
                        } else if (pathinfo($file, PATHINFO_EXTENSION) === 'js') {
                            // Scan JS files for obfuscated code
                            $scan_result = $this->scan_file_for_obfuscated_js($file);

                            if ($scan_result['suspicious']) {
                                $this->database->add_issue(
                                    $scan_id,
                                    'suspicious_js',
                                    $file,
                                    sprintf(__('Potentially obfuscated JavaScript found: %s', 'themewire-security'), $scan_result['reason']),
                                    'medium'
                                );
                                $issues_found++;

                                // Queue file for AI analysis
                                $this->ai_analyzer->queue_file_for_analysis($scan_id, $file);
                            }
                        }
                    }

                    // Save checkpoint after each batch
                    set_transient('twss_themes_scan_checkpoint_' . $scan_id, array(
                        'themes_scanned' => $themes_scanned,
                        'issues_found' => $issues_found,
                        'current_theme_index' => $i,
                        'current_file_index' => $batch_end
                    ), HOUR_IN_SECONDS);

                    $this->update_scan_activity();
                }
            }

            $themes_scanned++;
            $progress = round(($themes_scanned / $total_themes) * 100);

            $this->database->update_scan_progress(
                $scan_id,
                'themes',
                $progress,
                sprintf(__('Scanned %d of %d themes', 'themewire-security'), $themes_scanned, $total_themes)
            );

            // Save checkpoint after each theme
            set_transient('twss_themes_scan_checkpoint_' . $scan_id, array(
                'themes_scanned' => $themes_scanned,
                'issues_found' => $issues_found,
                'current_theme_index' => $i + 1,
                'current_file_index' => 0
            ), HOUR_IN_SECONDS);

            $this->update_scan_activity();
        }

        $this->database->update_scan_progress(
            $scan_id,
            'themes',
            100,
            sprintf(__('Theme scan complete. %d issues found.', 'themewire-security'), $issues_found)
        );

        // Cleanup checkpoint
        delete_transient('twss_themes_scan_checkpoint_' . $scan_id);
    }

    /**
     * Scan uploads directory with chunking to prevent timeouts
     *
     * @since    1.0.0
     * @param    int    $scan_id    The ID of the current scan
     */
    private function scan_uploads_directory($scan_id)
    {
        $uploads_dir = wp_upload_dir();

        if (!isset($uploads_dir['basedir']) || !is_dir($uploads_dir['basedir'])) {
            throw new Exception(__('Uploads directory not found', 'themewire-security'));
        }

        $this->database->update_scan_progress($scan_id, 'uploads', 0, 'Starting uploads directory scan');

        // Scan for PHP files in uploads directory (which is usually suspicious)
        $php_files = $this->find_php_files_in_uploads($uploads_dir['basedir']);

        // Check for checkpoint
        $checkpoint = get_transient('twss_uploads_scan_checkpoint_' . $scan_id);
        $files_scanned = 0;
        $issues_found = 0;

        if ($checkpoint) {
            $files_scanned = $checkpoint['files_scanned'];
            $issues_found = $checkpoint['issues_found'];
        }

        $total_files = count($php_files);

        if ($total_files > 0) {
            // Process files in chunks
            for ($i = $files_scanned; $i < $total_files; $i += $this->batch_size) {
                $batch_end = min($i + $this->batch_size, $total_files);

                for ($j = $i; $j < $batch_end; $j++) {
                    $file = $php_files[$j];

                    // Skip non-existent or unreadable files
                    if (!file_exists($file) || !is_readable($file)) {
                        continue;
                    }

                    $this->database->add_issue(
                        $scan_id,
                        'php_in_uploads',
                        $file,
                        __('PHP file found in uploads directory (potentially malicious)', 'themewire-security'),
                        'high'
                    );
                    $issues_found++;

                    // Queue file for AI analysis
                    $this->ai_analyzer->queue_file_for_analysis($scan_id, $file);
                }

                $files_scanned = $batch_end;
                $progress = round(($files_scanned / $total_files) * 100);

                // Save checkpoint after each batch
                set_transient('twss_uploads_scan_checkpoint_' . $scan_id, array(
                    'files_scanned' => $files_scanned,
                    'issues_found' => $issues_found
                ), HOUR_IN_SECONDS);

                $this->database->update_scan_progress(
                    $scan_id,
                    'uploads',
                    $progress,
                    sprintf(__('Scanning PHP files in uploads: %d of %d', 'themewire-security'), $files_scanned, $total_files)
                );

                $this->update_scan_activity();
            }
        }

        $this->database->update_scan_progress(
            $scan_id,
            'uploads',
            100,
            sprintf(__('Uploads directory scan complete. %d suspicious files found.', 'themewire-security'), $issues_found)
        );

        // Cleanup checkpoint
        delete_transient('twss_uploads_scan_checkpoint_' . $scan_id);
    }

    /**
     * Analyze scan results using AI with chunking to prevent timeouts
     *
     * @since    1.0.0
     * @param    int    $scan_id    The ID of the current scan
     */
    private function analyze_scan_results($scan_id)
    {
        $this->database->update_scan_progress($scan_id, 'ai_analysis', 0, 'Starting AI analysis of suspicious files');

        // Get files queued for analysis
        $files_for_analysis = $this->ai_analyzer->get_queued_files($scan_id);
        $total_files = count($files_for_analysis);

        if ($total_files === 0) {
            $this->database->update_scan_progress(
                $scan_id,
                'ai_analysis',
                100,
                __('No files needed AI analysis', 'themewire-security')
            );
            return;
        }

        // Check for checkpoint
        $checkpoint = get_transient('twss_ai_analysis_checkpoint_' . $scan_id);
        $files_analyzed = 0;

        if ($checkpoint) {
            $files_analyzed = $checkpoint['files_analyzed'];
        }

        // Process files in chunks
        for ($i = $files_analyzed; $i < $total_files; $i += $this->batch_size) {
            $batch_end = min($i + $this->batch_size, $total_files);

            for ($j = $i; $j < $batch_end; $j++) {
                $file = $files_for_analysis[$j];

                try {
                    $result = $this->ai_analyzer->analyze_file($file);

                    if ($result['is_malware']) {
                        $this->database->update_issue_status(
                            $scan_id,
                            $file,
                            'confirmed',
                            $result['explanation']
                        );

                        // Suggest fix if available
                        if (!empty($result['suggested_fix'])) {
                            $this->database->add_suggested_fix(
                                $scan_id,
                                $file,
                                $result['suggested_fix']
                            );
                        }
                    } else {
                        // False positive
                        $this->database->update_issue_status(
                            $scan_id,
                            $file,
                            'false_positive',
                            $result['explanation'] ?? 'AI analysis determined this is not malware'
                        );
                    }
                } catch (Exception $e) {
                    $error_message = $e->getMessage();

                    // Handle API quota/rate limiting
                    if (
                        strpos($error_message, 'quota') !== false ||
                        strpos($error_message, 'rate limited') !== false ||
                        strpos($error_message, 'temporarily unavailable') !== false
                    ) {

                        if ($this->logger) {
                            $this->logger->info('AI analysis unavailable for review, keeping original detection: ' . $file, array(
                                'reason' => 'API quota/rate limit'
                            ));
                        }

                        // Keep the original detection without AI confirmation
                        $this->database->update_issue_status(
                            $scan_id,
                            $file,
                            'pending',
                            'AI analysis unavailable - manual review recommended'
                        );
                    } else {
                        // Other errors - log and mark as needing review
                        if ($this->logger) {
                            $this->logger->error('Error during AI file review: ' . $file, array('error' => $error_message));
                        }

                        $this->database->update_issue_status(
                            $scan_id,
                            $file,
                            'review_needed',
                            'AI analysis failed - manual review required: ' . $error_message
                        );
                    }
                }
            }

            $files_analyzed = $batch_end;
            $progress = round(($files_analyzed / $total_files) * 100);

            // Save checkpoint after each batch
            set_transient('twss_ai_analysis_checkpoint_' . $scan_id, array(
                'files_analyzed' => $files_analyzed
            ), HOUR_IN_SECONDS);

            $this->database->update_scan_progress(
                $scan_id,
                'ai_analysis',
                $progress,
                sprintf(__('AI analysis: %d of %d files', 'themewire-security'), $files_analyzed, $total_files)
            );

            $this->update_scan_activity();
        }

        $this->database->update_scan_progress(
            $scan_id,
            'ai_analysis',
            100,
            sprintf(__('AI analysis complete. %d files analyzed.', 'themewire-security'), $total_files)
        );

        // Cleanup checkpoint
        delete_transient('twss_ai_analysis_checkpoint_' . $scan_id);
    }

    /**
     * Auto-fix issues if enabled
     *
     * @since    1.0.0
     * @param    int    $scan_id    The ID of the current scan
     */
    private function auto_fix_issues($scan_id)
    {
        // Get confirmed issues with suggested fixes
        $issues = $this->database->get_fixable_issues($scan_id);

        foreach ($issues as $issue) {
            $this->fixer->fix_issue($scan_id, $issue['file_path'], $issue['suggested_fix']);
        }
    }

    /**
     * Send notification email with scan results
     *
     * @since    1.0.0
     * @param    int     $scan_id    The ID of the current scan
     * @param    array   $summary    Scan summary data
     */
    private function send_notification_email($scan_id, $summary)
    {
        $to = get_option('admin_email');
        $subject = sprintf(__('[%s] Security Scan Results - %s', 'themewire-security'), get_bloginfo('name'), date('Y-m-d H:i'));

        $message = sprintf(
            __('Security scan completed on %s.', 'themewire-security'),
            date('Y-m-d H:i:s')
        );

        $message .= "\n\n";
        $message .= sprintf(__('Total issues found: %d', 'themewire-security'), $summary['total_issues']);
        $message .= "\n";
        $message .= sprintf(__('High severity: %d', 'themewire-security'), $summary['high_severity']);
        $message .= "\n";
        $message .= sprintf(__('Medium severity: %d', 'themewire-security'), $summary['medium_severity']);
        $message .= "\n";
        $message .= sprintf(__('Low severity: %d', 'themewire-security'), $summary['low_severity']);

        if ($summary['total_issues'] > 0) {
            $message .= "\n\n";
            $message .= __('Please log in to your WordPress dashboard to review and fix these issues.', 'themewire-security');
            $message .= "\n";
            $message .= admin_url('admin.php?page=themewire-security');
        }

        wp_mail($to, $subject, $message);
    }

    /**
     * Get WordPress checksums from API
     *
     * @since    1.0.0
     * @return   array|false    WordPress core checksums or false on failure
     */
    private function get_wordpress_checksums()
    {
        global $wp_version;

        // Check if we have cached checksums first
        $cache_key = 'twss_wp_checksums_' . $wp_version . '_' . get_locale();
        $cached_checksums = get_transient($cache_key);

        if ($cached_checksums !== false) {
            return $cached_checksums;
        }

        // Try the official WordPress API first
        $url = 'https://api.wordpress.org/core/checksums/1.0/';
        $url .= '?version=' . $wp_version . '&locale=' . get_locale();

        $response = wp_remote_get($url, array(
            'timeout' => 30, // Increase timeout
            'user-agent' => 'WordPress/' . $wp_version . '; ' . home_url('/'),
            'sslverify' => true
        ));

        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);

            if (is_array($data) && isset($data['checksums']) && is_array($data['checksums'])) {
                // Cache the checksums for 24 hours
                set_transient($cache_key, $data['checksums'], 24 * HOUR_IN_SECONDS);
                return $data['checksums'];
            }
        }

        // If official API fails, try our fallback approach - use a predefined list of core files
        $core_files = $this->get_fallback_core_files();

        if (!empty($core_files)) {
            // Cache the fallback checksums for 2 hours
            set_transient($cache_key, $core_files, 2 * HOUR_IN_SECONDS);
            return $core_files;
        }

        // If all fails, return false
        return false;
    }

    /**
     * Get a fallback list of WordPress core files when API fails
     *
     * @since    1.0.0
     * @return   array    List of core files (filename => md5 pairs)
     */
    private function get_fallback_core_files()
    {
        // This is a simplified approach - in a real plugin, you'd include a more comprehensive list
        // We'll just check for some essential core files
        $wp_root = ABSPATH;
        $core_files = array(
            'wp-login.php' => '',
            'wp-config-sample.php' => '',
            'wp-settings.php' => '',
            'wp-blog-header.php' => '',
            'wp-load.php' => '',
            'index.php' => '',
            'wp-includes/version.php' => '',
            'wp-includes/functions.php' => '',
            'wp-includes/plugin.php' => '',
            'wp-includes/class-wp.php' => '',
            'wp-admin/index.php' => '',
            'wp-admin/admin.php' => ''
        );

        // Generate checksums for these files
        foreach ($core_files as $file => $checksum) {
            $path = $wp_root . $file;
            if (file_exists($path)) {
                $core_files[$file] = md5_file($path);
            } else {
                unset($core_files[$file]);
            }
        }

        return $core_files;
    }

    /**
     * Scan directory recursively to get all files
     *
     * @since    1.0.0
     * @param    string    $dir    Directory path
     * @return   array     Array of file paths
     */
    private function scan_directory_recursively($dir)
    {
        $result = array();
        $files = scandir($dir);

        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }

            $path = $dir . '/' . $file;

            if (is_dir($path)) {
                $result = array_merge($result, $this->scan_directory_recursively($path));
            } else {
                $result[] = $path;
            }
        }

        return $result;
    }

    /**
     * Scan for extra files in core directories
     *
     * @since    1.0.0
     * @param    int       $scan_id       The ID of the current scan
     * @param    string    $base_dir      Base directory
     * @param    array     $known_files   List of known files
     * @param    string    $context       Context for reporting
     */
    private function scan_for_extra_files($scan_id, $base_dir, $known_files, $context)
    {
        // Convert array of file paths to a lookup hash for better performance
        $known_files_hash = array();
        foreach ($known_files as $file) {
            $known_files_hash[$file] = true;
        }

        // Find all PHP files in the directory
        $all_files = $this->find_php_files($base_dir);

        // Check for checkpoint
        $checkpoint = get_transient('twss_extra_files_scan_checkpoint_' . $scan_id);
        $files_checked = 0;

        if ($checkpoint) {
            $files_checked = $checkpoint['files_checked'];
        }

        $total_files = count($all_files);

        // Process files in chunks
        for ($i = $files_checked; $i < $total_files; $i += $this->batch_size) {
            $batch_end = min($i + $this->batch_size, $total_files);

            for ($j = $i; $j < $batch_end; $j++) {
                $file = $all_files[$j];

                // Skip non-existent or unreadable files
                if (!file_exists($file) || !is_readable($file)) {
                    continue;
                }

                // Convert to relative path for comparison with known_files
                $relative_path = str_replace($base_dir . '/', '', $file);

                if (!isset($known_files_hash[$relative_path])) {
                    // This file is not in the list of known files
                    $this->database->add_issue(
                        $scan_id,
                        'unknown_file',
                        $file,
                        sprintf(__('Unknown file found in %s directory', 'themewire-security'), $context),
                        'high'
                    );

                    // Queue file for AI analysis
                    $this->ai_analyzer->queue_file_for_analysis($scan_id, $file);
                }
            }

            $files_checked = $batch_end;

            // Save checkpoint after each batch
            set_transient('twss_extra_files_scan_checkpoint_' . $scan_id, array(
                'files_checked' => $files_checked
            ), HOUR_IN_SECONDS);

            $this->update_scan_activity();
        }

        // Cleanup checkpoint
        delete_transient('twss_extra_files_scan_checkpoint_' . $scan_id);
    }

    /**
     * Find all PHP files in a directory and its subdirectories (existing files only)
     *
     * @since    1.0.0
     * @param    string    $dir    Directory path
     * @return   array     Array of PHP file paths (verified to exist)
     */
    private function find_php_files($dir)
    {
        $result = array();

        // Validate directory exists and is readable
        if (!is_dir($dir) || !is_readable($dir)) {
            error_log("TWSS: Directory not accessible: {$dir}");
            return $result;
        }

        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($it as $file) {
                try {
                    // Skip if not a file
                    if (!$file->isFile()) {
                        continue;
                    }

                    // Skip if not PHP extension
                    if (strtolower($file->getExtension()) !== 'php') {
                        continue;
                    }

                    $filepath = $file->getPathname();
                    $realpath = realpath($filepath);

                    // Multiple layers of validation to ensure file actually exists
                    if (
                        // Basic existence check
                        file_exists($filepath) &&
                        // Ensure it's a regular file (not directory or special file)
                        is_file($filepath) &&
                        // Check if readable
                        is_readable($filepath) &&
                        // Ensure realpath resolves (not a broken symlink)
                        $realpath !== false &&
                        // Verify the resolved path also exists
                        file_exists($realpath) &&
                        // Ensure file has content (size check)
                        filesize($filepath) !== false &&
                        filesize($filepath) > 0 &&
                        // Final verification - can we actually read the file?
                        is_readable($realpath)
                    ) {
                        // Use realpath to avoid duplicate entries from symlinks
                        if (!in_array($realpath, $result)) {
                            $result[] = $realpath;
                        }
                    } else {
                        // Log ghost files that were skipped
                        error_log("TWSS: Skipped ghost/invalid file: {$filepath}");
                    }
                } catch (Exception $fileException) {
                    // Log individual file errors but continue processing
                    error_log('TWSS: Error processing file ' . $file->getPathname() . ': ' . $fileException->getMessage());
                    continue;
                }
            }
        } catch (Exception $e) {
            // Log error but continue - don't let directory access issues break the scan
            error_log('TWSS: Error scanning directory ' . $dir . ': ' . $e->getMessage());
        }

        // Log how many files were found
        error_log("TWSS: Found " . count($result) . " valid PHP files in {$dir}");

        return $result;
    }

    /**
     * Find PHP files in uploads directory
     *
     * @since    1.0.0
     * @param    string    $uploads_dir    Uploads directory path
     * @return   array     Array of PHP file paths
     */
    private function find_php_files_in_uploads($uploads_dir)
    {
        return $this->find_php_files($uploads_dir);
    }

    /**
     * Scan file for common malware patterns
     *
     * @since    1.0.0
     * @param    string    $file    File path
     * @return   array     Scan result with 'suspicious' flag, 'reason', and 'issues'
     */
    private function scan_file_for_malware($file)
    {
        // Validate file exists and is readable before scanning
        if (!file_exists($file) || !is_readable($file)) {
            return array(
                'suspicious' => false,
                'reason' => 'File not found or not readable',
                'issues' => array()
            );
        }

        $content = file_get_contents($file);
        if ($content === false) {
            return array(
                'suspicious' => false,
                'reason' => 'Failed to read file content',
                'issues' => array()
            );
        }

        $result = array(
            'suspicious' => false,
            'reason' => '',
            'issues' => array()
        );

        // Common malware patterns - Enhanced for better detection
        $patterns = array(
            'base64_decode' => '/base64_decode\s*\(/i',
            'eval' => '/eval\s*\(/i',
            'system' => '/system\s*\(/i',
            'shell_exec' => '/shell_exec\s*\(/i',
            'passthru' => '/passthru\s*\(/i',
            'exec' => '/exec\s*\(/i',
            'popen' => '/popen\s*\(/i',
            'proc_open' => '/proc_open\s*\(/i',
            'assert' => '/assert\s*\(/i',
            'str_rot13' => '/str_rot13\s*\(/i',
            'gzinflate' => '/gzinflate\s*\(/i',
            'gzuncompress' => '/gzuncompress\s*\(/i',
            'gzdecode' => '/gzdecode\s*\(/i',
            'base64' => '/(\'|")([\w+\/=]{30,})(\'|")/i',
            'iframe' => '/<iframe.*src\s*=\s*[\'"].*<\/iframe>/i',
            // Additional sophisticated malware patterns
            'eval_base64' => '/eval\s*\(\s*base64_decode/i',
            'eval_gzinflate' => '/eval\s*\(\s*gzinflate/i',
            'post_exec' => '/\$_POST.*exec/i',
            'get_exec' => '/\$_GET.*exec/i',
            'file_get_contents_http' => '/file_get_contents\s*\(\s*[\'"]https?:/i',
            'preg_replace_eval' => '/preg_replace\s*\([^,]*\/e/i',
            'create_function' => '/create_function\s*\(/i',
            'php_in_uploads' => strpos($file, 'wp-content/uploads') !== false && pathinfo($file, PATHINFO_EXTENSION) === 'php'
        );

        foreach ($patterns as $name => $pattern) {
            $is_match = false;

            if ($name === 'php_in_uploads') {
                $is_match = $pattern; // This is already a boolean
            } else {
                $is_match = preg_match($pattern, $content);
            }

            if ($is_match) {
                $result['suspicious'] = true;
                $result['reason'] = sprintf(__('Contains potential malware indicator: %s', 'themewire-security'), $name);

                // Add to issues array for compatibility
                $result['issues'][] = array(
                    'type' => 'malware',
                    'severity' => $this->get_pattern_severity($name),
                    'description' => $result['reason'],
                    'pattern' => $name,
                    'suggested_fix' => 'quarantine'
                );

                return $result; // Return immediately on first match
            }
        }

        // Check for heavily obfuscated code
        if ($this->is_heavily_obfuscated($content)) {
            $result['suspicious'] = true;
            $result['reason'] = __('Contains heavily obfuscated code', 'themewire-security');
            $result['issues'][] = array(
                'type' => 'obfuscation',
                'severity' => 'high',
                'description' => $result['reason'],
                'pattern' => 'obfuscation',
                'suggested_fix' => 'quarantine'
            );
            return $result;
        }

        return $result;
    }

    /**
     * Get severity level for a malware pattern
     *
     * @since    1.0.49
     * @param    string    $pattern_name    Pattern name
     * @return   string    Severity level
     */
    private function get_pattern_severity($pattern_name)
    {
        $high_severity = array('eval', 'eval_base64', 'eval_gzinflate', 'system', 'shell_exec', 'exec', 'php_in_uploads', 'post_exec', 'get_exec');
        $medium_severity = array('base64_decode', 'gzinflate', 'str_rot13', 'create_function', 'preg_replace_eval');

        if (in_array($pattern_name, $high_severity)) {
            return 'high';
        } elseif (in_array($pattern_name, $medium_severity)) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Check if a string is heavily obfuscated
     *
     * @since    1.0.0
     * @param    string    $content    The content to check
     * @return   boolean   True if heavily obfuscated
     */
    private function is_heavily_obfuscated($content)
    {
        // Check for very long lines (common in obfuscated code)
        if (preg_match('/^.{300,}$/m', $content)) {
            return true;
        }

        // Check for high ratio of special characters to total length
        $special_chars = preg_match_all('/[\^\$\*\(\)\[\]\{\}\?\+\.\\\\]/', $content, $matches);
        $total_length = strlen($content);

        if ($total_length > 0 && ($special_chars / $total_length) > 0.1) {
            return true;
        }

        return false;
    }

    /**
     * Scan JavaScript file for obfuscated code
     *
     * @since    1.0.0
     * @param    string    $file    File path
     * @return   array     Scan result with 'suspicious' flag and 'reason'
     */
    private function scan_file_for_obfuscated_js($file)
    {
        // Validate file exists and is readable before scanning
        if (!file_exists($file) || !is_readable($file)) {
            return array(
                'suspicious' => false,
                'reason' => 'File not found or not readable'
            );
        }

        $content = file_get_contents($file);
        if ($content === false) {
            return array(
                'suspicious' => false,
                'reason' => 'Failed to read file content'
            );
        }

        $result = array(
            'suspicious' => false,
            'reason' => ''
        );

        // Check for common obfuscation techniques in JS
        $patterns = array(
            'document_write' => '/document\.write\s*\(/i',
            'fromCharCode' => '/String\.fromCharCode\(/i',
            'eval' => '/eval\s*\(/i',
            'unescape' => '/unescape\s*\(/i',
            'encode_uri' => '/encodeURI\s*\(/i',
            'long_array_of_numbers' => '/\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+/i',
        );

        foreach ($patterns as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                $result['suspicious'] = true;
                $result['reason'] = sprintf(__('Contains potentially obfuscated JavaScript: %s', 'themewire-security'), $name);
                return $result;
            }
        }

        // Check if heavily obfuscated
        if ($this->is_heavily_obfuscated($content)) {
            $result['suspicious'] = true;
            $result['reason'] = __('Contains heavily obfuscated JavaScript code', 'themewire-security');
            return $result;
        }

        return $result;
    }

    /**
     * Check if a scan is in progress
     *
     * @since    1.0.0
     * @return   boolean   True if scan in progress
     */
    public function is_scan_in_progress()
    {
        $scan_status = get_transient('twss_scan_in_progress');
        return ($scan_status === 'yes');
    }

    /**
     * Set scan in progress status
     *
     * @since    1.0.0
     * @param    boolean   $status   Scan status
     */
    private function set_scan_in_progress($status)
    {
        if ($status) {
            set_transient('twss_scan_in_progress', 'yes', HOUR_IN_SECONDS);
        } else {
            delete_transient('twss_scan_in_progress');
        }
        $this->scan_in_progress = $status;
    }

    /**
     * Update scan progress for a specific stage
     *
     * @since    1.0.1
     * @param    int       $scan_id     The scan ID
     * @param    string    $stage       Stage name
     * @param    int       $progress    Progress percentage (0-100)
     * @param    string    $message     Progress message
     * @param    float     $weight      Stage weight for overall progress
     */
    private function update_scan_stage_progress($scan_id, $stage, $progress, $message)
    {
        $this->database->update_scan_progress($scan_id, $stage, $progress, $message);
        $this->update_scan_activity();
    }

    /**
     * Stop the current scan
     *
     * @since    1.0.2
     * @return   array     Result array with success status and message
     */
    public function stop_scan()
    {
        try {
            // Clear the scan in progress flag
            $this->set_scan_in_progress(false);

            // Clear all scan checkpoints
            $this->clear_scan_checkpoints();

            // Update the scan status to stopped
            $current_scan_id = get_transient('twss_current_scan_id');
            if ($current_scan_id) {
                $this->database->update_scan_status($current_scan_id, 'stopped', 'Scan stopped by user');
                delete_transient('twss_current_scan_id');
            }

            return array(
                'success' => true,
                'message' => __('Scan stopped successfully', 'themewire-security')
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => __('Error stopping scan: ', 'themewire-security') . $e->getMessage()
            );
        }
    }

    /**
     * Clear all scan checkpoint transients
     *
     * @since    1.0.2
     */
    public function clear_scan_checkpoints()
    {
        $current_scan_id = get_transient('twss_current_scan_id');
        if ($current_scan_id) {
            // Clear various checkpoint transients
            delete_transient('twss_core_scan_checkpoint_' . $current_scan_id);
            delete_transient('twss_plugins_scan_checkpoint_' . $current_scan_id);
            delete_transient('twss_themes_scan_checkpoint_' . $current_scan_id);
            delete_transient('twss_uploads_scan_checkpoint_' . $current_scan_id);
            delete_transient('twss_ai_analysis_checkpoint_' . $current_scan_id);
            delete_transient('twss_extra_files_scan_checkpoint_' . $current_scan_id);
        }
    }

    /**
     * Finalize a chunked scan
     *
     * @since    1.0.23
     * @param    int $scan_id The scan ID
     * @return   array Result of finalization
     */
    private function finalize_chunked_scan($scan_id)
    {
        // Get scan state to calculate total files scanned before cleaning up
        $scan_state = get_transient('twss_chunked_scan_state');
        $files_scanned = 0;

        // Try to calculate files scanned from various sources
        if ($scan_state) {
            // If scan state tracks files, use that
            if (isset($scan_state['files_scanned'])) {
                $files_scanned = $scan_state['files_scanned'];
            } else {
                // Estimate from scan progress messages - look for various patterns
                global $wpdb;
                $progress_messages = $wpdb->get_results($wpdb->prepare(
                    "SELECT message FROM {$wpdb->prefix}twss_scan_progress WHERE scan_id = %d ORDER BY timestamp DESC",
                    $scan_id
                ), ARRAY_A);

                foreach ($progress_messages as $progress) {
                    $message = $progress['message'];
                    // Try different message patterns
                    if (preg_match('/(\d+)\/(\d+) files scanned/', $message, $matches)) {
                        $files_scanned = max($files_scanned, intval($matches[1]));
                    } elseif (preg_match('/(\d+) files scanned/', $message, $matches)) {
                        $files_scanned = max($files_scanned, intval($matches[1]));
                    } elseif (preg_match('/Scanned (\d+) files/', $message, $matches)) {
                        $files_scanned = max($files_scanned, intval($matches[1]));
                    }
                }

                // If still 0, count unique issues as a minimum estimate
                if ($files_scanned === 0) {
                    $unique_files = $wpdb->get_var($wpdb->prepare(
                        "SELECT COUNT(DISTINCT file_path) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d",
                        $scan_id
                    ));
                    $files_scanned = max($files_scanned, intval($unique_files));
                }

                // Final fallback: estimate based on scan progress entries (each entry ~= 10-20 files)
                if ($files_scanned === 0) {
                    $progress_count = count($progress_messages);
                    $files_scanned = max(1, $progress_count * 15); // Conservative estimate
                }
            }
        }        // Update scan status to completed
        $this->database->update_scan_status($scan_id, 'completed');
        $this->logger->info('COMPLETION DEBUG: Chunked scan completed', array('scan_id' => $scan_id, 'files_scanned' => $files_scanned));

        // Update the total files count in database with estimated scanned files
        if ($files_scanned > 0) {
            $db_update_result = $this->database->update_scan_total_files($scan_id, $files_scanned);
            if ($db_update_result === false) {
                error_log("TWSS ERROR: Failed to update scan total files (chunked scan) for scan_id: $scan_id, files: $files_scanned");
                error_log("TWSS ERROR: This suggests a database connection issue in Docker/DevKinsta environment");
            } else {
                error_log("TWSS SUCCESS: Database update succeeded (chunked scan) for scan_id: $scan_id, files: $files_scanned");
            }
        } else {
            $this->logger->info('COMPLETION DEBUG: Chunked scan files_scanned is 0, not updating database', array('scan_id' => $scan_id));
        }

        // Clean up scan state - ensure all transients are cleared
        delete_transient('twss_chunked_scan_state');
        delete_transient('twss_scan_in_progress'); // Explicitly clear scan progress flag
        delete_transient('twss_scan_last_activity');
        delete_option('twss_current_scan_id');

        $this->set_scan_in_progress(false);

        if ($this->logger) {
            $this->logger->info('Chunked scan completed successfully', array('scan_id' => $scan_id));
        }

        // Get scan summary
        $summary = $this->database->get_scan_summary($scan_id);

        return array(
            'success' => true,
            'scan_id' => $scan_id,
            'stage' => 'completed',
            'progress' => 100,
            'message' => __('Scan completed successfully!', 'themewire-security'),
            'continue' => false,
            'summary' => $summary
        );
    }

    /**
     * Scan a single file for malware and security issues
     *
     * @since    1.0.28
     * @param    int $scan_id The scan ID
     * @param    string $file_path Path to the file to scan
     * @param    string $file_type Type of file (core, plugin, theme, upload)
     * @return   array Scan results
     */
    private function scan_file($scan_id, $file_path, $file_type)
    {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return array(
                'success' => false,
                'message' => 'File not accessible: ' . $file_path
            );
        }

        // Skip if file is too large
        if (filesize($file_path) > 10 * 1024 * 1024) { // 10MB limit
            return array(
                'success' => true,
                'message' => 'Skipped large file: ' . $file_path
            );
        }

        $results = array();

        // Scan for malware signatures
        $malware_result = $this->scan_file_for_malware($file_path);
        if (!empty($malware_result['issues'])) {
            foreach ($malware_result['issues'] as $issue) {
                $metadata = json_encode(array(
                    'line_number' => isset($issue['line_number']) ? $issue['line_number'] : 0,
                    'code_snippet' => isset($issue['code_snippet']) ? $issue['code_snippet'] : '',
                    'detection_type' => 'malware'
                ));

                $this->database->record_issue(
                    $scan_id,
                    $file_path,
                    'malware',
                    $issue['severity'],
                    $issue['description'],
                    '',
                    $metadata
                );
            }
            $results = array_merge($results, $malware_result['issues']);
        }

        // For JS files, also scan for obfuscation
        if (pathinfo($file_path, PATHINFO_EXTENSION) === 'js') {
            $obfuscation_result = $this->scan_file_for_obfuscated_js($file_path);
            if (!empty($obfuscation_result['issues'])) {
                foreach ($obfuscation_result['issues'] as $issue) {
                    $metadata = json_encode(array(
                        'line_number' => isset($issue['line_number']) ? $issue['line_number'] : 0,
                        'code_snippet' => isset($issue['code_snippet']) ? $issue['code_snippet'] : '',
                        'detection_type' => 'obfuscation'
                    ));

                    $this->database->record_issue(
                        $scan_id,
                        $file_path,
                        'obfuscation',
                        $issue['severity'],
                        $issue['description'],
                        '',
                        $metadata
                    );
                }
                $results = array_merge($results, $obfuscation_result['issues']);
            }
        }

        return array(
            'success' => true,
            'issues_found' => count($results),
            'issues' => $results
        );
    }

    /**
     * Get core files for scanning
     *
     * @since    1.0.28
     * @return   array    Array of core file paths
     */
    private function get_core_files()
    {
        $core_dir = ABSPATH;
        return $this->get_prioritized_files($core_dir, 1000);
    }

    /**
     * Get plugin files for scanning
     *
     * @since    1.0.28
     * @return   array    Array of plugin file paths
     */
    private function get_plugin_files()
    {
        $plugin_dir = WP_PLUGIN_DIR;
        if (!is_dir($plugin_dir)) {
            return array();
        }

        $plugin_files = array();

        // Get active plugins only to avoid scanning inactive ones
        $active_plugins = get_option('active_plugins', array());
        foreach ($active_plugins as $plugin) {
            $plugin_path = $plugin_dir . '/' . dirname($plugin);
            if (is_dir($plugin_path)) {
                $files = $this->find_php_files($plugin_path);
                $plugin_files = array_merge($plugin_files, $files);
            }
        }

        // Add network plugins for multisite
        if (is_multisite()) {
            $network_plugins = get_site_option('active_sitewide_plugins', array());
            foreach (array_keys($network_plugins) as $plugin) {
                $plugin_path = $plugin_dir . '/' . dirname($plugin);
                if (is_dir($plugin_path)) {
                    $files = $this->find_php_files($plugin_path);
                    $plugin_files = array_merge($plugin_files, $files);
                }
            }
        }

        return array_unique($plugin_files);
    }

    /**
     * Get theme files for scanning
     *
     * @since    1.0.28
     * @return   array    Array of theme file paths
     */
    private function get_theme_files()
    {
        $themes_dir = get_theme_root();
        if (!is_dir($themes_dir)) {
            return array();
        }

        $theme_files = array();

        // Get active theme
        $active_theme = wp_get_theme();
        $active_theme_path = $themes_dir . '/' . $active_theme->get_stylesheet();
        if (is_dir($active_theme_path)) {
            $files = $this->find_php_files($active_theme_path);
            $theme_files = array_merge($theme_files, $files);
        }

        // Add parent theme if child theme is active
        if ($active_theme->parent()) {
            $parent_theme_path = $themes_dir . '/' . $active_theme->get_template();
            if (is_dir($parent_theme_path)) {
                $files = $this->find_php_files($parent_theme_path);
                $theme_files = array_merge($theme_files, $files);
            }
        }

        return array_unique($theme_files);
    }

    /**
     * Get upload files for scanning (looking for PHP files in uploads)
     *
     * @since    1.0.28
     * @return   array    Array of upload file paths
     */
    private function get_upload_files()
    {
        $uploads_dir = wp_upload_dir();
        if (!isset($uploads_dir['basedir']) || !is_dir($uploads_dir['basedir'])) {
            return array();
        }

        // Find PHP files in uploads (which are usually suspicious)
        return $this->find_php_files($uploads_dir['basedir']);
    }

    /**
     * Process core files chunk for chunked scanning (fixed implementation)
     *
     * @since    1.0.28
     * @param    int $scan_id The scan ID
     * @param    array $scan_state Current scan state
     * @return   array Chunk processing result
     */
    private function process_core_files_chunk($scan_id, $scan_state)
    {
        if ($scan_state['batch_offset'] == 0) {
            // First chunk - get all core files
            $core_files = $this->get_core_files();
            set_transient('twss_scan_core_files', $core_files, HOUR_IN_SECONDS);

            if (empty($core_files)) {
                return array(
                    'stage_complete' => true,
                    'next_stage' => 'plugins',
                    'progress' => 100,
                    'next_offset' => 0,
                    'message' => __('Core scan completed - no files found', 'themewire-security')
                );
            }
        } else {
            // Get cached core files list
            $core_files = get_transient('twss_scan_core_files');
            if (!$core_files) {
                $core_files = $this->get_core_files();
            }
        }

        if (empty($core_files)) {
            return array(
                'stage_complete' => true,
                'next_stage' => 'plugins',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Core scan completed - no files found', 'themewire-security')
            );
        }

        $batch_size = $this->batch_size;
        $offset = $scan_state['batch_offset'];
        $files_chunk = array_slice($core_files, $offset, $batch_size);

        if (empty($files_chunk)) {
            delete_transient('twss_scan_core_files');
            return array(
                'stage_complete' => true,
                'next_stage' => 'plugins',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Core files scanned successfully', 'themewire-security')
            );
        }

        $files_scanned = 0;
        $start_time = time();

        foreach ($files_chunk as $file_info) {
            $file_path = isset($file_info['path']) ? $file_info['path'] : $file_info;
            $this->scan_file($scan_id, $file_path, 'core');
            $files_scanned++;

            if ((time() - $start_time) > $this->chunk_time_limit) {
                break;
            }
        }

        $total_files = count($core_files);
        $processed_files = $offset + $files_scanned;
        $progress = min(100, ($processed_files / $total_files) * 100);

        $this->database->update_scan_progress(
            $scan_id,
            'core',
            $progress,
            sprintf(__('Scanned %d of %d core files', 'themewire-security'), $processed_files, $total_files)
        );

        return array(
            'stage_complete' => ($processed_files >= $total_files),
            'next_stage' => 'plugins',
            'progress' => $progress,
            'next_offset' => $offset + $files_scanned,
            'message' => sprintf(__('Processing core files... %d/%d', 'themewire-security'), $processed_files, $total_files)
        );
    }

    /**
     * Process plugins chunk for chunked scanning
     *
     * @since    1.0.23
     * @param    int $scan_id The scan ID
     * @param    array $scan_state Current scan state
     * @return   array Chunk processing result
     */
    private function process_plugins_chunk($scan_id, $scan_state)
    {
        if ($scan_state['batch_offset'] == 0) {
            // First chunk - get all plugin files
            $plugin_files = $this->get_plugin_files();
            set_transient('twss_scan_plugin_files', $plugin_files, HOUR_IN_SECONDS);
        } else {
            // Get cached plugin files list
            $plugin_files = get_transient('twss_scan_plugin_files');
            if (!$plugin_files) {
                $plugin_files = $this->get_plugin_files();
            }
        }

        if (empty($plugin_files)) {
            return array(
                'stage_complete' => true,
                'next_stage' => 'themes',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Plugin scan completed - no plugins found', 'themewire-security')
            );
        }

        $batch_size = $this->batch_size;
        $offset = $scan_state['batch_offset'];

        // Get chunk of files to process
        $files_chunk = array_slice($plugin_files, $offset, $batch_size);

        if (empty($files_chunk)) {
            delete_transient('twss_scan_plugin_files');

            return array(
                'stage_complete' => true,
                'next_stage' => 'themes',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Plugin files scanned successfully', 'themewire-security')
            );
        }

        // Process this chunk of files
        $files_scanned = 0;
        $start_time = time();

        foreach ($files_chunk as $file_path) {
            $this->scan_file($scan_id, $file_path, 'plugin');
            $files_scanned++;

            // Check time limit
            if ((time() - $start_time) > $this->chunk_time_limit) {
                break;
            }
        }

        // Calculate progress
        $total_files = count($plugin_files);
        $processed_files = $offset + $files_scanned;
        $progress = min(100, ($processed_files / $total_files) * 100);

        $this->database->update_scan_progress(
            $scan_id,
            'plugins',
            $progress,
            sprintf(__('Scanned %d of %d plugin files', 'themewire-security'), $processed_files, $total_files)
        );

        return array(
            'stage_complete' => ($processed_files >= $total_files),
            'next_stage' => 'themes',
            'progress' => $progress,
            'next_offset' => $offset + $files_scanned,
            'message' => sprintf(__('Processing plugin files... %d/%d', 'themewire-security'), $processed_files, $total_files)
        );
    }

    /**
     * Process themes chunk for chunked scanning
     *
     * @since    1.0.23
     * @param    int $scan_id The scan ID
     * @param    array $scan_state Current scan state
     * @return   array Chunk processing result
     */
    private function process_themes_chunk($scan_id, $scan_state)
    {
        if ($scan_state['batch_offset'] == 0) {
            $theme_files = $this->get_theme_files();
            set_transient('twss_scan_theme_files', $theme_files, HOUR_IN_SECONDS);
        } else {
            $theme_files = get_transient('twss_scan_theme_files');
            if (!$theme_files) {
                $theme_files = $this->get_theme_files();
            }
        }

        if (empty($theme_files)) {
            return array(
                'stage_complete' => true,
                'next_stage' => 'uploads',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Theme scan completed - no themes found', 'themewire-security')
            );
        }

        $batch_size = $this->batch_size;
        $offset = $scan_state['batch_offset'];
        $files_chunk = array_slice($theme_files, $offset, $batch_size);

        if (empty($files_chunk)) {
            delete_transient('twss_scan_theme_files');

            return array(
                'stage_complete' => true,
                'next_stage' => 'uploads',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Theme files scanned successfully', 'themewire-security')
            );
        }

        $files_scanned = 0;
        $start_time = time();

        foreach ($files_chunk as $file_path) {
            $this->scan_file($scan_id, $file_path, 'theme');
            $files_scanned++;

            if ((time() - $start_time) > $this->chunk_time_limit) {
                break;
            }
        }

        $total_files = count($theme_files);
        $processed_files = $offset + $files_scanned;
        $progress = min(100, ($processed_files / $total_files) * 100);

        $this->database->update_scan_progress(
            $scan_id,
            'themes',
            $progress,
            sprintf(__('Scanned %d of %d theme files', 'themewire-security'), $processed_files, $total_files)
        );

        return array(
            'stage_complete' => ($processed_files >= $total_files),
            'next_stage' => 'uploads',
            'progress' => $progress,
            'next_offset' => $offset + $files_scanned,
            'message' => sprintf(__('Processing theme files... %d/%d', 'themewire-security'), $processed_files, $total_files)
        );
    }

    /**
     * Process uploads chunk for chunked scanning
     *
     * @since    1.0.23
     * @param    int $scan_id The scan ID
     * @param    array $scan_state Current scan state
     * @return   array Chunk processing result
     */
    private function process_uploads_chunk($scan_id, $scan_state)
    {
        if ($scan_state['batch_offset'] == 0) {
            $upload_files = $this->get_upload_files();
            set_transient('twss_scan_upload_files', $upload_files, HOUR_IN_SECONDS);
        } else {
            $upload_files = get_transient('twss_scan_upload_files');
            if (!$upload_files) {
                $upload_files = $this->get_upload_files();
            }
        }

        if (empty($upload_files)) {
            return array(
                'stage_complete' => true,
                'next_stage' => 'ai_analysis',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Upload scan completed - no files found', 'themewire-security')
            );
        }

        $batch_size = $this->batch_size;
        $offset = $scan_state['batch_offset'];
        $files_chunk = array_slice($upload_files, $offset, $batch_size);

        if (empty($files_chunk)) {
            delete_transient('twss_scan_upload_files');

            return array(
                'stage_complete' => true,
                'next_stage' => 'ai_analysis',
                'progress' => 100,
                'next_offset' => 0,
                'message' => __('Upload files scanned successfully', 'themewire-security')
            );
        }

        $files_scanned = 0;
        $start_time = time();

        foreach ($files_chunk as $file_path) {
            $this->scan_file($scan_id, $file_path, 'upload');
            $files_scanned++;

            if ((time() - $start_time) > $this->chunk_time_limit) {
                break;
            }
        }

        $total_files = count($upload_files);
        $processed_files = $offset + $files_scanned;
        $progress = min(100, ($processed_files / $total_files) * 100);

        $this->database->update_scan_progress(
            $scan_id,
            'uploads',
            $progress,
            sprintf(__('Scanned %d of %d upload files', 'themewire-security'), $processed_files, $total_files)
        );

        return array(
            'stage_complete' => ($processed_files >= $total_files),
            'next_stage' => 'ai_analysis',
            'progress' => $progress,
            'next_offset' => $offset + $files_scanned,
            'message' => sprintf(__('Processing upload files... %d/%d', 'themewire-security'), $processed_files, $total_files)
        );
    }

    /**
     * Process AI analysis chunk for chunked scanning
     *
     * @since    1.0.23
     * @param    int $scan_id The scan ID
     * @param    array $scan_state Current scan state
     * @return   array Chunk processing result
     */
    private function process_ai_analysis_chunk($scan_id, $scan_state)
    {
        $batch_size = 10; // Analyze 10 files per batch to avoid timeouts
        $offset = isset($scan_state['ai_offset']) ? $scan_state['ai_offset'] : 0;

        // Get files that need AI analysis using the new database method
        $pending_files = $this->database->get_files_pending_ai_analysis($scan_id, $batch_size, $offset);

        $processed = 0;
        $total_pending = count($pending_files); // This will be corrected below

        if (empty($pending_files)) {
            // AI analysis complete
            $scan_state['ai_analysis_complete'] = true;
            $scan_state['stage'] = 'completed';
            $scan_state['completed'] = true;

            $this->logger->info('AI analysis completed for all files', array('scan_id' => $scan_id));

            // Update the optimized scan state
            set_transient('twss_optimized_scan_state', $scan_state, DAY_IN_SECONDS);

            // Finalize the scan
            return $this->finalize_optimized_scan($scan_state);
        }

        // Process files through AI analysis
        foreach ($pending_files as $file_data) {
            try {
                $ai_result = $this->ai_analyzer->analyze_file($file_data->file_path);

                // Extract AI analysis results
                $risk_score = 0;
                $threats = array();

                if ($ai_result && isset($ai_result['is_malware']) && $ai_result['is_malware']) {
                    $risk_score = isset($ai_result['confidence']) ? $ai_result['confidence'] : 75;
                    $threats = isset($ai_result['indicators']) ? $ai_result['indicators'] : array('malware_detected');

                    // **CRITICAL FIX**: Create issue record when AI detects malware
                    $confidence = isset($ai_result['confidence']) ? $ai_result['confidence'] : 75;
                    $explanation = isset($ai_result['explanation']) ? $ai_result['explanation'] : 'AI detected malicious content during comprehensive analysis';
                    $suggested_fix = isset($ai_result['suggested_fix']) ? $ai_result['suggested_fix'] : 'quarantine';

                    // Determine severity based on confidence
                    $severity = 'medium'; // Default
                    if ($confidence >= 80) {
                        $severity = 'high';
                    } elseif ($confidence < 50) {
                        $severity = 'low';
                    }

                    // Record the issue in the issues table
                    $this->database->record_issue(
                        $scan_id,
                        $file_data->file_path,
                        'malware',
                        $severity,
                        $explanation,
                        $suggested_fix,
                        json_encode(array(
                            'confidence' => $confidence,
                            'scan_stage' => 'ai_analysis',
                            'ai_detected' => true,
                            'indicators' => $threats
                        ))
                    );

                    $this->logger->warning('AI Analysis detected malicious file', array(
                        'file' => $file_data->file_path,
                        'confidence' => $confidence,
                        'scan_id' => $scan_id,
                        'threats' => $threats
                    ));
                } else {
                    $risk_score = 0;
                    $threats = array();
                }

                // Update scan results with AI analysis using new database method
                $this->database->update_ai_analysis_result($scan_id, $file_data->file_path, $risk_score, $threats);

                $processed++;
            } catch (Exception $e) {
                $this->logger->error('AI analysis failed for file: ' . $file_data->file_path, array(
                    'error' => $e->getMessage(),
                    'scan_id' => $scan_id
                ));

                // Mark as analyzed to avoid infinite loop
                $this->database->update_ai_analysis_result($scan_id, $file_data->file_path, 0, array());
            }
        }

        // Update progress
        $scan_state['ai_offset'] = $offset + $batch_size;
        $progress_percentage = $batch_size > 0 ? (($offset + $processed) / ($offset + $batch_size)) * 100 : 100;
        $scan_state['progress'] = min(95 + ($progress_percentage * 0.05), 99); // 95-99% range for AI analysis

        set_transient('twss_optimized_scan_state', $scan_state, DAY_IN_SECONDS);

        $this->logger->info('AI analysis batch completed', array(
            'scan_id' => $scan_id,
            'processed' => $processed,
            'offset' => $offset,
            'progress' => $scan_state['progress']
        ));

        return array(
            'success' => true,
            'continue' => true,
            'stage' => 'ai_analysis',
            'progress' => $scan_state['progress'],
            'message' => sprintf(__('AI analyzing files... %d%% complete', 'themewire-security'), round($scan_state['progress']))
        );
    }

    // =======================
    // OPTIMIZED SCANNING HELPER METHODS
    // =======================

    /**
     * Reset scan state completely
     *
     * @since    1.0.29
     */
    private function reset_scan_state()
    {
        delete_transient('twss_scan_in_progress');
        delete_transient('twss_scan_last_activity');
        delete_transient('twss_chunked_scan_state');
        delete_transient('twss_optimized_scan_state');
    }

    /**
     * Find critical files that need immediate scanning
     *
     * @since    1.0.29
     * @return   array    Array of critical file paths
     */
    private function find_critical_files()
    {
        $critical_files = array();

        // 1. PHP files in uploads directory (highest priority)
        $uploads_dir = wp_upload_dir();
        if (isset($uploads_dir['basedir']) && is_dir($uploads_dir['basedir'])) {
            $upload_php_files = $this->find_files_by_extension($uploads_dir['basedir'], array('php', 'phtml', 'php3', 'php4', 'php5'));
            $critical_files = array_merge($critical_files, $upload_php_files);
        }

        // 2. Hidden files and suspicious filenames
        $suspicious_patterns = array('.htaccess', 'wp-config.php', 'index.php');
        $wp_root = ABSPATH;

        foreach ($suspicious_patterns as $pattern) {
            $files = glob($wp_root . '*' . $pattern);
            foreach ($files as $file) {
                if (is_file($file) && $this->is_suspicious_location($file, basename($file))) {
                    $critical_files[] = $file;
                }
            }
        }

        // 3. Recently modified files (last 30 days)
        $recent_files = $this->find_recently_modified_files($wp_root, 30);
        $critical_files = array_merge($critical_files, $recent_files);

        return array_unique($critical_files);
    }

    /**
     * Find sample core files for scanning (not all core files for speed)
     *
     * @since    1.0.29
     * @return   array    Array of core file paths
     */
    /**
     * Find ALL WordPress core files for comprehensive security scanning
     *
     * @since    1.0.29
     * @return   array    Array of ALL core file paths
     */
    private function find_all_core_files()
    {
        $core_files = array();
        $wp_root = ABSPATH;

        // Key WordPress core files that are often targeted
        $key_files = array(
            'wp-config.php',
            'wp-load.php',
            'wp-blog-header.php',
            'index.php',
            '.htaccess',
            'wp-cron.php',
            'wp-login.php',
            'wp-settings.php',
            'wp-mail.php',
            'wp-activate.php',
            'wp-signup.php',
            'wp-trackback.php',
            'wp-comments-post.php',
            'wp-links-opml.php'
        );

        foreach ($key_files as $file) {
            $full_path = $wp_root . $file;
            if (is_file($full_path)) {
                $core_files[] = $full_path;
            }
        }

        // ALL wp-includes files (comprehensive scan)
        $includes_files = $this->find_files_by_extension($wp_root . 'wp-includes', $this->priority_extensions, 0);
        if ($includes_files) {
            $core_files = array_merge($core_files, $includes_files);
        }

        // ALL wp-admin files (comprehensive scan)
        $admin_files = $this->find_files_by_extension($wp_root . 'wp-admin', $this->priority_extensions, 0);
        if ($admin_files) {
            $core_files = array_merge($core_files, $admin_files);
        }

        $this->logger->info('Found WordPress core files for comprehensive scan', array('count' => count($core_files)));

        return array_unique($core_files);
    }

    /**
     * Find active plugin files only
     *
     * @since    1.0.29
     * @return   array    Array of active plugin file paths
     */
    /**
     * Find ALL plugin files (active AND inactive) for comprehensive security scanning
     *
     * @since    1.0.29
     * @return   array    Array of ALL plugin file paths
     */
    private function find_all_plugin_files()
    {
        $plugin_files = array();
        $plugin_dir = WP_PLUGIN_DIR;

        if (!is_dir($plugin_dir)) {
            return array();
        }

        // Get ALL plugins (both active and inactive for security)
        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', array());

        // Scan ALL plugin directories (not just active ones)
        $plugin_directories = glob($plugin_dir . '/*', GLOB_ONLYDIR);

        foreach ($plugin_directories as $plugin_path) {
            if (is_dir($plugin_path)) {
                // No file limit - comprehensive security scan
                $files = $this->find_files_by_extension($plugin_path, $this->priority_extensions, 0);
                $plugin_files = array_merge($plugin_files, $files);
            }
        }

        // Add network plugins for multisite
        if (function_exists('is_multisite') && is_multisite()) {
            $network_plugins = get_site_option('active_sitewide_plugins', array());
            // Network plugins already included in directory scan above
        }

        $this->logger->info('Found plugin files for comprehensive scan', array('count' => count($plugin_files)));

        return array_unique($plugin_files);
    }

    /**
     * Find active theme files only
     *
     * @since    1.0.29
     * @return   array    Array of active theme file paths
     */
    /**
     * Find ALL theme files (active AND inactive) for comprehensive security scanning
     *
     * @since    1.0.29
     * @return   array    Array of ALL theme file paths
     */
    private function find_all_theme_files()
    {
        $theme_files = array();
        $themes_dir = function_exists('get_theme_root') ? get_theme_root() : WP_CONTENT_DIR . '/themes';

        if (!is_dir($themes_dir)) {
            return array();
        }

        // Scan ALL theme directories (not just active theme)
        $theme_directories = glob($themes_dir . '/*', GLOB_ONLYDIR);

        foreach ($theme_directories as $theme_path) {
            if (is_dir($theme_path)) {
                // No file limit - comprehensive security scan
                $files = $this->find_files_by_extension($theme_path, $this->priority_extensions, 0);
                $theme_files = array_merge($theme_files, $files);
            }
        }

        $this->logger->info('Found theme files for comprehensive scan', array('count' => count($theme_files)));

        return array_unique($theme_files);
    }

    /**
     * Find ALL uploads directory files for comprehensive security scanning
     *
     * @since    1.0.29
     * @return   array    Array of ALL upload file paths
     */
    private function find_all_upload_files()
    {
        $uploads_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : array('basedir' => WP_CONTENT_DIR . '/uploads');
        if (!isset($uploads_dir['basedir']) || !is_dir($uploads_dir['basedir'])) {
            return array();
        }

        // Find ALL files that could pose security risks
        $comprehensive_extensions = array(
            // PHP variants
            'php',
            'phtml',
            'php3',
            'php4',
            'php5',
            'php7',
            'php8',
            // Scripting files
            'js',
            'html',
            'htm',
            'asp',
            'aspx',
            'jsp',
            'py',
            'pl',
            'cgi',
            // Executable files
            'exe',
            'bat',
            'cmd',
            'sh',
            'bin',
            // Archive files (can contain malware)
            'zip',
            'rar',
            '7z',
            'tar',
            'gz',
            // Configuration files
            'htaccess',
            'htpasswd',
            'ini',
            'conf',
            'config'
        );

        $upload_files = $this->find_files_by_extension($uploads_dir['basedir'], $comprehensive_extensions, 0);

        $this->logger->info('Found upload files for comprehensive scan', array('count' => count($upload_files)));

        return $upload_files;
    }

    /**
     * Find files by extension with optional limit
     *
     * @since    1.0.29
     * @param    string    $directory    Directory to search
     * @param    array     $extensions   File extensions to find
     * @param    int       $limit        Optional limit on number of files
     * @return   array     Array of file paths
     */
    private function find_files_by_extension($directory, $extensions, $limit = 0)
    {
        $files = array();
        $count = 0;

        if (!is_dir($directory)) {
            $this->logger->info("File discovery: Directory does not exist: $directory");
            return array();
        }

        $this->logger->info("File discovery: Scanning directory: $directory for extensions: " . implode(', ', $extensions));

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($limit > 0 && $count >= $limit) {
                break;
            }

            if ($file->isFile()) {
                $extension = strtolower($file->getExtension());
                if (in_array($extension, $extensions)) {
                    $files[] = $file->getPathname();
                    $count++;
                }
            }
        }

        $this->logger->info("File discovery: Found $count files in $directory (limit: $limit)");
        return $files;
    }

    /**
     * Detect basic file issues using pattern matching for corruption and malware
     *
     * @since    1.0.29
     * @param    string    $file_path     File path
     * @param    string    $file_content  File content
     * @return   array     Array of detected issues
     */
    private function detect_basic_file_issues($file_path, $file_content)
    {
        $issues = array();
        $file_extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));

        // Skip binary files and very large files
        if (empty($file_content) || strlen($file_content) > 5 * 1024 * 1024) {
            return $issues;
        }

        // Common malware patterns - ENHANCED FOR SOPHISTICATED MALWARE
        $malware_patterns = array(
            'eval\s*\(\s*base64_decode' => 'Base64 obfuscated code execution',
            'eval\s*\(\s*gzinflate' => 'Compressed obfuscated code',
            'eval\s*\(\s*str_rot13' => 'ROT13 obfuscated code',
            'system\s*\(\s*\$_' => 'Direct system command execution',
            'exec\s*\(\s*\$_' => 'Direct command execution',
            'shell_exec\s*\(\s*\$_' => 'Shell command execution',
            'passthru\s*\(\s*\$_' => 'Command passthrough execution',
            'file_get_contents\s*\(\s*["\']http' => 'Remote file inclusion',
            'curl_exec\s*\(' => 'Suspicious CURL usage',
            'fsockopen\s*\(' => 'Network socket connection',
            'base64_decode\s*\(\s*["\'][A-Za-z0-9+/=]{100,}' => 'Large base64 encoded data',
            '\$GLOBALS\s*\[\s*["\']_' => 'Global variable manipulation',
            'chr\s*\(\s*\d+\s*\)\s*\.' => 'Character encoding obfuscation',
            'create_function\s*\(' => 'Dynamic function creation',
            'preg_replace\s*\([^,]*\/e' => 'Deprecated code execution via regex',
            'assert\s*\(\s*\$_' => 'Code execution via assert',
            '\$_POST\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(' => 'POST data execution',
            '\$_GET\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(' => 'GET data execution',
            'mail\s*\([^)]*\$_' => 'Email spam functionality',
            // ENHANCED PATTERNS FOR SOPHISTICATED MALWARE
            'function\s+\w+\(\$\w+,\s*\$\w+,\s*\$\w+\)\s*\{\s*global\s+\$\w+;' => 'Suspicious function with global variable manipulation',
            'chr\(\d+\)\s*\.\s*chr\(\d+\)' => 'Heavy character obfuscation (backdoor indicator)',
            '\$\w+\s*=\s*chr\(\d+\)' => 'Character-based string obfuscation',
            'unserialize\s*\(\s*\$' => 'Unsafe deserialization (RCE risk)',
            'array_map\s*\(\s*["\'][\w]+[\'"]' => 'Array function obfuscation',
            'str_rot13\s*\(\s*base64_decode' => 'Double obfuscation (ROT13 + Base64)',
            'rawurldecode\s*\(' => 'URL decode obfuscation',
            'implode\s*\(\s*["\'][\'"]' => 'String reconstruction obfuscation',
            '\$_SERVER\s*\[\s*["\']DOCUMENT_ROOT[\'"]' => 'Server path manipulation',
            'glob\s*\(\s*\$\w+\s*\.\s*["\']\/\*[\'"]' => 'Directory traversal pattern',
            'file_put_contents\s*\([^,]*\$_' => 'Dynamic file writing (backdoor creation)',
            'fwrite\s*\(\s*fopen\s*\([^,]*\$_' => 'Direct file manipulation',
            'wp_remote_get\s*\(\s*["\']https?:\/\/[^"\']+\.php' => 'Suspicious remote PHP execution',
            'add_action\s*\(\s*["\']wp_footer[\'"],\s*function' => 'Malicious WordPress hook injection',
            'base64_decode\s*\(\s*\$_' => 'User-controlled base64 decode',
            '<\?php\s+\$\w+\s*=\s*[\'"]\w+[\'"];\s*eval' => 'PHP eval backdoor pattern',
            '\$\w+\s*=\s*[\'"][a-zA-Z0-9+\/=]{50,}[\'"];\s*eval' => 'Encoded eval backdoor',
            '\$\w+\s*\(\s*\$\w+\s*\^\s*\$\w+\)' => 'XOR encryption/decryption (sophisticated malware)',
            'foreach\s*\(\s*\$_POST\s+as\s+\$\w+\s*=>' => 'POST data processing without validation'
        );

        // File corruption patterns
        $corruption_patterns = array(
            'Fatal error.*in.*on line' => 'PHP fatal error in file',
            'Parse error.*in.*on line' => 'PHP parse error in file',
            'syntax error.*in.*on line' => 'PHP syntax error in file',
            '\x00{10,}' => 'Multiple null bytes (potential corruption)'
        );

        // Check for malware patterns
        foreach ($malware_patterns as $pattern => $description) {
            if (preg_match('/' . $pattern . '/i', $file_content)) {
                $issues[] = array(
                    'type' => 'malware',
                    'severity' => 'high',
                    'description' => 'Suspicious pattern detected: ' . $description,
                    'suggested_fix' => 'quarantine',
                    'pattern' => $pattern
                );
            }
        }

        // Check for corruption patterns
        foreach ($corruption_patterns as $pattern => $description) {
            if (preg_match('/' . $pattern . '/s', $file_content)) {
                $issues[] = array(
                    'type' => 'corruption',
                    'severity' => 'medium',
                    'description' => 'File corruption detected: ' . $description,
                    'suggested_fix' => 'restore_backup',
                    'pattern' => $pattern
                );
            }
        }

        // PHP-specific checks
        if (in_array($file_extension, array('php', 'phtml'))) {
            // Check for WordPress-specific malware
            $wp_suspicious = array(
                'add_action\s*\(\s*["\']wp_head["\'].*base64_decode' => 'Malicious wp_head hook',
                'add_action\s*\(\s*["\']init["\'].*eval' => 'Malicious init hook',
                'add_filter\s*\(\s*["\']the_content["\'].*base64' => 'Content filter malware'
            );

            foreach ($wp_suspicious as $pattern => $description) {
                if (preg_match('/' . $pattern . '/i', $file_content)) {
                    $issues[] = array(
                        'type' => 'malware',
                        'severity' => 'critical',
                        'description' => 'WordPress-specific malware: ' . $description,
                        'suggested_fix' => 'quarantine',
                        'pattern' => $pattern
                    );
                }
            }
        }

        return $issues;
    }

    /**
     * Find recently modified files
     *
     * @since    1.0.29
     * @param    string    $directory    Directory to search
     * @param    int       $days         Number of days to look back
     * @return   array     Array of recently modified file paths
     */
    private function find_recently_modified_files($directory, $days = 30)
    {
        $recent_files = array();
        $cutoff_time = time() - ($days * 24 * 60 * 60);

        if (!is_dir($directory)) {
            return array();
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        $count = 0;
        foreach ($iterator as $file) {
            if ($count >= 100) { // Limit for performance
                break;
            }

            if ($file->isFile() && $file->getMTime() > $cutoff_time) {
                $extension = strtolower($file->getExtension());
                if (in_array($extension, $this->priority_extensions)) {
                    $recent_files[] = $file->getPathname();
                    $count++;
                }
            }
        }

        return $recent_files;
    }

    /**
     * Check if file is in suspicious location
     *
     * @since    1.0.29
     * @param    string    $file_path    File path
     * @param    string    $filename     Filename
     * @return   boolean   True if suspicious
     */
    private function is_suspicious_location($file_path, $filename)
    {
        // Files in uploads directory
        if (strpos($file_path, 'wp-content/uploads') !== false) {
            return true;
        }

        // Hidden files
        if ($filename[0] === '.') {
            return true;
        }

        // Duplicate core files in wrong locations
        $suspicious_files = array('wp-config.php', 'index.php', '.htaccess');
        if (in_array($filename, $suspicious_files)) {
            // Check if it's not in the expected location
            if (!strpos($file_path, ABSPATH . $filename)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get files for current scan stage
     *
     * @since    1.0.29
     * @param    string    $stage       Current stage
     * @param    array     $scan_state  Current scan state
     * @return   array     Files to scan
     */
    private function get_files_for_stage($stage, $scan_state)
    {
        $files_per_batch = 15;
        $offset = isset($scan_state['stage_offset']) ? $scan_state['stage_offset'] : 0;

        switch ($stage) {
            case 'critical_files':
                $files = $this->find_critical_files();
                break;
            case 'core_files':
                $files = $this->find_all_core_files();
                break;
            case 'plugins':
                $files = $this->find_all_plugin_files();
                break;
            case 'themes':
                $files = $this->find_all_theme_files();
                break;
            case 'uploads':
                $files = $this->find_all_upload_files();
                break;
            default:
                return array();
        }

        // Return slice of files for this batch
        return array_slice($files, $offset, $files_per_batch);
    }

    /**
     * Get next scan stage
     *
     * @since    1.0.29
     * @param    string    $current_stage    Current stage
     * @return   string|null    Next stage or null if completed
     */
    private function get_next_scan_stage($current_stage)
    {
        $stages = array('critical_files', 'core_files', 'plugins', 'themes', 'uploads');
        $current_index = array_search($current_stage, $stages);

        if ($current_index === false || $current_index >= count($stages) - 1) {
            return null; // No more stages
        }

        return $stages[$current_index + 1];
    }

    /**
     * Calculate overall progress percentage
     *
     * @since    1.0.29
     * @param    array    $scan_state    Current scan state
     * @return   int      Progress percentage
     */
    private function calculate_overall_progress($scan_state)
    {
        if ($scan_state['total_files'] == 0) {
            return 0;
        }

        return min(100, intval(($scan_state['files_scanned'] / $scan_state['total_files']) * 100));
    }

    /**
     * Calculate stage progress percentage
     *
     * @since    1.0.29
     * @param    array    $scan_state    Current scan state
     * @return   int      Stage progress percentage
     */
    private function calculate_stage_progress($scan_state)
    {
        $stage = $scan_state['stage'];
        $stage_totals = $scan_state['stage_totals'];

        if (!isset($stage_totals[$stage]) || $stage_totals[$stage] == 0) {
            return 100;
        }

        $stage_offset = isset($scan_state['stage_offset']) ? $scan_state['stage_offset'] : 0;
        return min(100, intval(($stage_offset / $stage_totals[$stage]) * 100));
    }

    /**
     * Optimized file scanning method
     *
     * @since    1.0.29
     * @param    int       $scan_id     Scan ID
     * @param    string    $file_path   File path
     * @param    string    $stage       Current stage
     * @return   array     Scan result
     */
    private function scan_file_optimized($scan_id, $file_path, $stage)
    {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return array('success' => false, 'issues_found' => 0);
        }

        // Skip large files for speed
        if (filesize($file_path) > 5 * 1024 * 1024) { // 5MB limit
            return array('success' => true, 'issues_found' => 0, 'skipped' => 'file_too_large');
        }

        $results = array();

        // Quick malware scan
        $malware_result = $this->scan_file_for_malware($file_path);
        if (!empty($malware_result['issues'])) {
            foreach ($malware_result['issues'] as $issue) {
                $metadata = json_encode(array(
                    'line_number' => isset($issue['line_number']) ? $issue['line_number'] : 0,
                    'code_snippet' => isset($issue['code_snippet']) ? $issue['code_snippet'] : '',
                    'detection_type' => 'malware',
                    'stage' => $stage
                ));

                $this->database->record_issue(
                    $scan_id,
                    $file_path,
                    'malware',
                    $issue['severity'],
                    $issue['description'],
                    '',
                    $metadata
                );
            }
            $results = array_merge($results, $malware_result['issues']);
        }

        return array(
            'success' => true,
            'issues_found' => count($results),
            'issues' => $results
        );
    }

    /**
     * Finalize optimized scan
     *
     * @since    1.0.29
     * @param    array    $scan_state    Current scan state
     * @return   array    Finalization result
     */
    private function finalize_optimized_scan($scan_state)
    {
        $scan_id = $scan_state['scan_id'];

        // Final safety check - make sure we've actually completed enough files
        if ($scan_state['files_scanned'] < ($scan_state['total_files'] * 0.90)) {
            // Don't finalize if less than 90% completed - something went wrong
            error_log("TWSS Warning: Attempted to finalize scan with only " .
                $scan_state['files_scanned'] . "/" . $scan_state['total_files'] . " files scanned");

            // Reset to last stage and continue
            $scan_state['stage'] = 'uploads'; // Force to last stage
            $scan_state['stage_offset'] = 0;
            set_transient('twss_optimized_scan_state', $scan_state, DAY_IN_SECONDS);

            return array(
                'success' => true,
                'message' => 'Scan continuation required - not enough files processed',
                'files_processed' => 0,
                'files_scanned' => $scan_state['files_scanned'],
                'total_files' => $scan_state['total_files'],
                'overall_progress' => $this->calculate_overall_progress($scan_state),
                'current_stage' => 'Uploads',
                'continue' => true
            );
        }

        // Mark scan as completed
        $this->database->update_scan_status($scan_id, 'completed');

        // FIXED: Use the inventory total as the primary source of files count
        // The inventory calculation is accurate and should be trusted
        $final_files_count = $scan_state['total_files'] ?? 0;

        // If scan_state total_files is 0 or missing, recalculate the inventory
        if ($final_files_count === 0) {
            // Recalculate the file inventory directly
            $fresh_inventory = $this->calculate_scan_inventory();
            $inventory_total = $fresh_inventory['total_files'] ?? 0;

            if ($inventory_total > 0) {
                $final_files_count = $inventory_total;
            } else {
                // Get the ACTUAL number of files scanned from the database as fallback
                $comprehensive_stats = $this->database->get_comprehensive_scan_stats($scan_id);
                $final_files_count = isset($comprehensive_stats['total_files']) ? $comprehensive_stats['total_files'] : 0;

                // Final fallback to scan state files_scanned
                if ($final_files_count === 0) {
                    $final_files_count = $scan_state['files_scanned'];
                }
            }
        }

        // Add debug logging
        $this->logger->info("Finalizing scan $scan_id - Using inventory total: $final_files_count files, scan_state shows " .
            $scan_state['files_scanned'] . " files_scanned");

        // Add more debug info about what we're using
        $this->logger->info("Scan completion debug", array(
            'scan_id' => $scan_id,
            'final_files_count' => $final_files_count,
            'scan_state_files_scanned' => $scan_state['files_scanned'],
            'scan_state_total_files' => $scan_state['total_files'] ?? 'not_set',
            'source' => 'inventory_total'
        ));

        // DOCKER/DEVKINSTA FIX: Check if database update succeeded
        $db_update_result = $this->database->update_scan_total_files($scan_id, $final_files_count);
        if ($db_update_result === false) {
            error_log("TWSS ERROR: Failed to update scan total files for scan_id: $scan_id, files: $final_files_count");
            error_log("TWSS ERROR: This suggests a database connection issue in Docker/DevKinsta environment");

            // Try to update scan status to indicate database issue
            $this->database->update_scan_status($scan_id, 'failed', 'Database update failed - connection issue');
        } else {
            error_log("TWSS SUCCESS: Database update succeeded for scan_id: $scan_id, files: $final_files_count");
        }

        $this->set_scan_in_progress(false);

        // Store completion info for status checking
        update_option('twss_last_completed_scan_id', $scan_id);
        update_option('twss_last_scan_completion_time', time());

        // Get scan summary and store issues count
        $summary = $this->database->get_scan_summary($scan_id);
        $issues_found = isset($summary['total_issues']) ? $summary['total_issues'] : 0;
        update_option('twss_last_scan_issues_found', $issues_found);

        // Clean up transients and options - ensure all scan state is cleared
        delete_transient('twss_optimized_scan_state');
        delete_transient('twss_scan_in_progress'); // Explicitly clear scan progress flag
        delete_transient('twss_scan_last_activity');
        delete_option('twss_current_scan_id');

        return array(
            'success' => true,
            'scan_id' => $scan_id,
            'stage' => 'completed',
            'progress' => 100,
            'files_scanned' => $scan_state['files_scanned'],
            'total_files' => $scan_state['total_files'],
            'message' => sprintf(
                __('Scan completed! Scanned %d files in %d seconds.', 'themewire-security'),
                $scan_state['files_scanned'],
                time() - $scan_state['started']
            ),
            'continue' => false,
            'summary' => $summary
        );
    }

    /**
     * Check if a stage has been completed relative to current stage
     *
     * @since    1.0.30
     * @param    string   $current_stage   Current scan stage
     * @param    string   $check_stage     Stage to check
     * @return   boolean  True if stage is completed
     */
    private function stage_completed($current_stage, $check_stage)
    {
        $stage_order = array('critical_files', 'core_files', 'plugins', 'themes', 'uploads');
        $current_index = array_search($current_stage, $stage_order);
        $check_index = array_search($check_stage, $stage_order);

        return $current_index > $check_index;
    }

    /**
     * Estimate remaining scan time
     *
     * @since    1.0.30
     * @param    array    $scan_state        Current scan state
     * @param    int      $files_processed   Files processed in this chunk
     * @param    int      $chunk_duration    Duration of this chunk
     * @return   string   Formatted remaining time estimate
     */
    private function estimate_remaining_time($scan_state, $files_processed, $chunk_duration)
    {
        $remaining_files = $scan_state['total_files'] - $scan_state['files_scanned'];

        if ($remaining_files <= 0 || $files_processed <= 0) {
            return '0 seconds';
        }

        $files_per_second = $files_processed / max($chunk_duration, 1);
        $estimated_seconds = $remaining_files / $files_per_second;

        if ($estimated_seconds < 60) {
            return round($estimated_seconds) . ' seconds';
        } elseif ($estimated_seconds < 3600) {
            return round($estimated_seconds / 60) . ' minutes';
        } else {
            return round($estimated_seconds / 3600, 1) . ' hours';
        }
    }

    /**
     * Get scan status for real-time updates
     *
     * @since    1.0.30
     * @return   array    Current scan status
     */
    public function get_scan_status()
    {
        $scan_state = get_transient('twss_optimized_scan_state');
        if (!$scan_state) {
            // Check if there's a recently completed scan
            $recent_scan_id = get_option('twss_last_completed_scan_id', 0);
            if ($recent_scan_id) {
                $scan_completion_time = get_option('twss_last_scan_completion_time', 0);
                // If scan was completed within the last 30 seconds, return completion status
                if ($scan_completion_time && (time() - $scan_completion_time) < 30) {
                    return array(
                        'success' => true,
                        'status' => 'completed',
                        'scan_id' => $recent_scan_id,
                        'message' => 'Scan completed successfully',
                        'issues_found' => get_option('twss_last_scan_issues_found', 0),
                        'recently_completed' => true,
                        'completion_time' => $scan_completion_time
                    );
                }
            }

            // Check if there's a regular scan running as fallback
            $legacy_scan_id = get_option('twss_current_scan_id', 0);
            if ($legacy_scan_id) {
                return array(
                    'success' => true,
                    'legacy_scan' => true,
                    'scan_id' => $legacy_scan_id,
                    'status' => 'running',
                    'message' => 'Legacy scan in progress'
                );
            }

            return array(
                'success' => false,
                'message' => 'No active scan found',
                'debug' => array(
                    'transient_exists' => false,
                    'legacy_scan_id' => $legacy_scan_id,
                    'recent_scan_id' => $recent_scan_id,
                    'timestamp' => time()
                )
            );
        }

        $overall_progress = $this->calculate_overall_progress($scan_state);
        $elapsed_time = time() - $scan_state['started'];

        // Check if scan is completed - handles all completion scenarios
        $is_completed = false;

        // Explicit completion flag
        if (isset($scan_state['completed']) && $scan_state['completed']) {
            $is_completed = true;
        }
        // AI analysis stage completed (final stage)
        elseif (
            $scan_state['stage'] === 'ai_analysis' &&
            isset($scan_state['ai_analysis_complete']) && $scan_state['ai_analysis_complete']
        ) {
            $is_completed = true;
        }
        // All files scanned and reached final stage
        elseif (($scan_state['stage'] === 'uploads' || $scan_state['stage'] === 'ai_analysis') &&
            $scan_state['files_scanned'] >= $scan_state['total_files']
        ) {
            $is_completed = true;
        }
        // Stage marked as 'completed'
        elseif ($scan_state['stage'] === 'completed') {
            $is_completed = true;
        }

        return array(
            'success' => true,
            'optimized' => true,  // Add optimized flag
            'status' => $is_completed ? 'completed' : 'running', // Dynamic status
            'scan_active' => !$is_completed,
            'scan_id' => $scan_state['scan_id'],
            'files_scanned' => $scan_state['files_scanned'],
            'total_files' => $scan_state['total_files'],
            'overall_progress' => $is_completed ? 100 : $overall_progress,
            'current_stage' => ucfirst(str_replace('_', ' ', $scan_state['stage'])),
            'current_directory' => $scan_state['current_directory'] ? basename($scan_state['current_directory']) : 'Starting...',
            'elapsed_time' => $elapsed_time,
            'files_per_second' => $scan_state['files_scanned'] > 0 ? round($scan_state['files_scanned'] / max($elapsed_time, 1), 2) : 0,
            'stage_breakdown' => $scan_state['stage_totals'],
            'scan_state' => $scan_state,  // Add full scan state for detailed progress tracking
            'issues_found' => isset($scan_state['issues_found']) ? $scan_state['issues_found'] : 0,
            'debug' => array(
                'stage_offset' => isset($scan_state['stage_offset']) ? $scan_state['stage_offset'] : 0,
                'stage_total' => isset($scan_state['stage_totals'][$scan_state['stage']]) ? $scan_state['stage_totals'][$scan_state['stage']] : 0,
                'transient_age' => time() - (isset($scan_state['last_update']) ? $scan_state['last_update'] : $scan_state['started'])
            )
        );
    }
}
