<?php

/**
 * The file scanner functionality of the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 * @last-modified 2025-07-14 23:08:50
 * @modified-by josephjerryrhule
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
     * Scan batch size for chunking large scans
     * 
     * @since    1.0.1
     * @access   private
     * @var      int    $batch_size
     */
    private $batch_size = 100;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     */
    public function __construct()
    {
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

        // Try to increase PHP time limit for long-running scans
        $this->increase_execution_time();
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

        if ($this->logger) {
            $this->logger->info('Starting new security scan');
        }

        // Set scan in progress and record activity time
        $this->set_scan_in_progress(true);
        $this->update_scan_activity();

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
            if ($this->logger) {
                $this->logger->info('Scan completed successfully', array('scan_id' => $scan_id));
            }

            // Get scan summary
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
        $current_plugin_index = 0;
        $current_file_index = 0;

        if ($checkpoint) {
            $plugins_scanned = $checkpoint['plugins_scanned'];
            $issues_found = $checkpoint['issues_found'];
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
                        $result['explanation']
                    );
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
     * @return   array     Scan result with 'suspicious' flag and 'reason'
     */
    private function scan_file_for_malware($file)
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

        // Common malware patterns
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
        );

        foreach ($patterns as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                $result['suspicious'] = true;
                $result['reason'] = sprintf(__('Contains potential malware indicator: %s', 'themewire-security'), $name);
                return $result;
            }
        }

        // Check for heavily obfuscated code
        if ($this->is_heavily_obfuscated($content)) {
            $result['suspicious'] = true;
            $result['reason'] = __('Contains heavily obfuscated code', 'themewire-security');
            return $result;
        }

        return $result;
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
}
