<?php

/**
 * Database functionality for storing scan results.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Database
{

    /**
     * Initialize the class
     *
     * @since    1.0.0
     */
    public function __construct()
    {
        // Validate database connection on instantiation
        $this->validate_database_connection();

        // Create tables if they don't exist
        add_action('plugins_loaded', array($this, 'create_tables'));
    }

    /**
     * Validate database connection for Docker/DevKinsta environments
     *
     * @since    1.0.0
     * @return   bool    True if connection is valid
     */
    private function validate_database_connection()
    {
        global $wpdb;

        // Check if $wpdb is available
        if (!isset($wpdb) || !is_object($wpdb)) {
            error_log('TWSS Database: WordPress database object not available');
            return false;
        }

        // Test database connection with a simple query
        $connection_test = $wpdb->get_var("SELECT 1");

        if ($connection_test !== '1') {
            error_log('TWSS Database: Connection test failed - ' . $wpdb->last_error);
            return false;
        }

        // Additional Docker/DevKinsta specific checks
        $this->check_environment_compatibility();

        return true;
    }

    /**
     * Check environment compatibility for Docker/DevKinsta
     *
     * @since    1.0.0
     */
    private function check_environment_compatibility()
    {
        global $wpdb;

        // Check MySQL version compatibility (logging disabled to reduce FastCGI spam)
        $mysql_version = $wpdb->get_var("SELECT VERSION()");
        // if ($mysql_version) {
        //     error_log('TWSS Database: MySQL version detected - ' . $mysql_version);
        // }

        // Check table prefix (logging disabled to reduce FastCGI spam)
        $prefix = $wpdb->prefix;
        // error_log('TWSS Database: Using table prefix - ' . $prefix);

        // Check charset (logging disabled to reduce FastCGI spam)
        $charset = $wpdb->get_charset_collate();
        // error_log('TWSS Database: Using charset - ' . $charset);
    }

    /**
     * Create database tables if they don't exist
     *
     * @since    1.0.0
     */
    public function create_tables()
    {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Scans table
        $table_scans = $wpdb->prefix . 'twss_scans';
        $sql_scans = "CREATE TABLE $table_scans (
            id int(11) NOT NULL AUTO_INCREMENT,
            scan_date datetime NOT NULL,
            status varchar(20) NOT NULL,
            total_files int(11) NOT NULL DEFAULT 0,
            issues_found int(11) NOT NULL DEFAULT 0,
            issues_fixed int(11) NOT NULL DEFAULT 0,
            error_message text,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        // Issues table
        $table_issues = $wpdb->prefix . 'twss_issues';
        $sql_issues = "CREATE TABLE $table_issues (
            id int(11) NOT NULL AUTO_INCREMENT,
            scan_id int(11) NOT NULL,
            issue_type varchar(50) NOT NULL,
            file_path varchar(512) NOT NULL,
            description text NOT NULL,
            severity varchar(20) NOT NULL,
            status varchar(20) NOT NULL DEFAULT 'pending',
            ai_analysis text,
            suggested_fix text,
            date_detected datetime NOT NULL,
            date_fixed datetime,
            PRIMARY KEY  (id),
            KEY scan_id (scan_id)
        ) $charset_collate;";

        // Scan progress table
        $table_progress = $wpdb->prefix . 'twss_scan_progress';
        $sql_progress = "CREATE TABLE $table_progress (
            id int(11) NOT NULL AUTO_INCREMENT,
            scan_id int(11) NOT NULL,
            stage varchar(50) NOT NULL,
            progress int(3) NOT NULL,
            message text,
            timestamp datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY scan_id (scan_id)
        ) $charset_collate;";

        // Whitelist table
        $table_whitelist = $wpdb->prefix . 'twss_whitelist';
        $sql_whitelist = "CREATE TABLE $table_whitelist (
            id int(11) NOT NULL AUTO_INCREMENT,
            file_path varchar(512) NOT NULL,
            reason text,
            date_added datetime NOT NULL,
            added_by varchar(50),
            PRIMARY KEY  (id),
            UNIQUE KEY file_path (file_path)
        ) $charset_collate;";

        // Scan results table for comprehensive file analysis
        $table_scan_results = $wpdb->prefix . 'twss_scan_results';
        $sql_scan_results = "CREATE TABLE $table_scan_results (
            id int(11) NOT NULL AUTO_INCREMENT,
            scan_id int(11) NOT NULL,
            file_path varchar(512) NOT NULL,
            file_size int(11) NOT NULL DEFAULT 0,
            file_hash varchar(64),
            file_content longtext,
            pattern_matches text,
            ai_analyzed tinyint(1) NOT NULL DEFAULT 0,
            ai_risk_score int(3) NOT NULL DEFAULT 0,
            ai_threats text,
            scan_stage varchar(50) NOT NULL,
            timestamp datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY scan_id (scan_id),
            KEY file_path (file_path),
            KEY ai_analyzed (ai_analyzed)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql_scans);
        dbDelta($sql_issues);
        dbDelta($sql_progress);
        dbDelta($sql_whitelist);
        dbDelta($sql_scan_results);
    }

    /**
     * Create a new scan record
     *
     * @since    1.0.0
     * @return   int    The new scan ID
     */
    public function create_new_scan_record()
    {
        global $wpdb;

        $wpdb->insert(
            $wpdb->prefix . 'twss_scans',
            array(
                'scan_date' => current_time('mysql'),
                'status' => 'in_progress',
                'total_files' => 0,
                'issues_found' => 0,
                'issues_fixed' => 0
            )
        );

        return $wpdb->insert_id;
    }

    /**
     * Update scan status
     *
     * @since    1.0.0
     * @param    int       $scan_id          The scan ID
     * @param    string    $status           The new status
     * @param    string    $error_message    Optional error message
     */
    public function update_scan_status($scan_id, $status, $error_message = '')
    {
        global $wpdb;

        $data = array(
            'status' => $status
        );

        if (!empty($error_message)) {
            $data['error_message'] = $error_message;
        }

        $wpdb->update(
            $wpdb->prefix . 'twss_scans',
            $data,
            array('id' => $scan_id)
        );
    }

    /**
     * Update scan progress
     *
     * @since    1.0.0
     * @param    int       $scan_id     The scan ID
     * @param    string    $stage       The scan stage
     * @param    int       $progress    The progress percentage
     * @param    string    $message     Progress message
     */
    public function update_scan_progress($scan_id, $stage, $progress, $message)
    {
        global $wpdb;

        $wpdb->insert(
            $wpdb->prefix . 'twss_scan_progress',
            array(
                'scan_id' => $scan_id,
                'stage' => $stage,
                'progress' => $progress,
                'message' => $message,
                'timestamp' => current_time('mysql')
            )
        );
    }

    /**
     * Update scan total files count
     *
     * @since    1.0.0
     * @param    int    $scan_id      The scan ID
     * @param    int    $total_files  The total number of files scanned
     */
    public function update_scan_total_files($scan_id, $total_files)
    {
        global $wpdb;

        // Add debug logging
        error_log("TWSS Debug: Database update_scan_total_files called for scan_id: $scan_id, total_files: $total_files");

        $result = $wpdb->update(
            $wpdb->prefix . 'twss_scans',
            array('total_files' => $total_files),
            array('id' => $scan_id)
        );

        // Log the result
        error_log("TWSS Debug: Database update result: " . ($result !== false ? "success ($result rows affected)" : "failed"));

        return $result;
    }

    /**
     * Add an issue to the database
     *
     * @since    1.0.0
     * @param    int       $scan_id       The scan ID
     * @param    string    $issue_type    The type of issue
     * @param    string    $file_path     Path to the file
     * @param    string    $description   Issue description
     * @param    string    $severity      Issue severity (high, medium, low)
     * @return   int       The issue ID
     */
    public function add_issue($scan_id, $issue_type, $file_path, $description, $severity)
    {
        global $wpdb;

        // Check if file is whitelisted
        if ($this->is_file_whitelisted($file_path)) {
            return false;
        }

        // Enhanced file validation to prevent ghost files
        // Skip validation only for specific issue types that are about missing files
        $skip_existence_validation = in_array($issue_type, [
            'core_file_missing',
            'plugin_file_missing',
            'theme_file_missing'
        ]);

        if (!$skip_existence_validation) {
            // Multiple layers of validation to ensure file actually exists
            $realpath = realpath($file_path);

            if (
                // Basic existence check
                !file_exists($file_path) ||
                // Ensure it's a regular file (not directory or special file)
                !is_file($file_path) ||
                // Check if readable
                !is_readable($file_path) ||
                // Ensure realpath resolves (not a broken symlink)
                $realpath === false ||
                // Verify the resolved path also exists
                !file_exists($realpath) ||
                // Ensure file has content (size check)
                filesize($file_path) === false ||
                filesize($file_path) <= 0
            ) {
                // Log ghost files that were skipped
                error_log("TWSS: Skipped adding issue for non-existent/invalid file: {$file_path} (Type: {$issue_type})");
                return false;
            }

            // Use realpath for consistent file path storage
            $file_path = $realpath;
        }

        $wpdb->insert(
            $wpdb->prefix . 'twss_issues',
            array(
                'scan_id' => $scan_id,
                'issue_type' => $issue_type,
                'file_path' => $file_path,
                'description' => $description,
                'severity' => $severity,
                'status' => 'pending',
                'date_detected' => current_time('mysql')
            )
        );

        // Update the issues_found count in the scans table
        $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}twss_scans SET issues_found = issues_found + 1 WHERE id = %d",
            $scan_id
        ));

        return $wpdb->insert_id;
    }

    /**
     * Record a security issue (alternative method name for add_issue)
     *
     * @since    1.0.27
     * @param    int       $scan_id       The scan ID
     * @param    string    $file_path     Path to the file
     * @param    string    $issue_type    The type of issue
     * @param    string    $severity      Issue severity (high, medium, low)
     * @param    string    $description   Issue description
     * @param    string    $suggested_fix Suggested fix
     * @param    string    $metadata      Additional metadata as JSON (stored in ai_analysis field)
     * @return   int       The issue ID
     */
    public function record_issue($scan_id, $file_path, $issue_type, $severity, $description, $suggested_fix = '', $metadata = '')
    {
        // Call the existing add_issue method with parameters in correct order
        $issue_id = $this->add_issue($scan_id, $issue_type, $file_path, $description, $severity);

        if ($issue_id && $suggested_fix) {
            $this->add_suggested_fix($scan_id, $file_path, $suggested_fix);
        }

        // Store metadata in ai_analysis field if provided
        if ($issue_id && $metadata) {
            global $wpdb;
            $table_issues = $wpdb->prefix . 'twss_issues';
            $wpdb->update(
                $table_issues,
                array('ai_analysis' => $metadata),
                array('id' => $issue_id),
                array('%s'),
                array('%d')
            );
        }

        return $issue_id;
    }

    /**
     * Update issue status
     *
     * @since    1.0.0
     * @param    int       $scan_id      The scan ID
     * @param    string    $file_path    Path to the file
     * @param    string    $status       New status
     * @param    string    $ai_analysis  AI analysis result
     */
    public function update_issue_status($scan_id, $file_path, $status, $ai_analysis = '')
    {
        global $wpdb;

        $data = array(
            'status' => $status
        );

        if (!empty($ai_analysis)) {
            $data['ai_analysis'] = $ai_analysis;
        }

        $wpdb->update(
            $wpdb->prefix . 'twss_issues',
            $data,
            array(
                'scan_id' => $scan_id,
                'file_path' => $file_path
            )
        );
    }

    /**
     * Add suggested fix for an issue
     *
     * @since    1.0.0
     * @param    int       $scan_id        The scan ID
     * @param    string    $file_path      Path to the file
     * @param    string    $suggested_fix  The suggested fix
     */
    public function add_suggested_fix($scan_id, $file_path, $suggested_fix)
    {
        global $wpdb;

        $wpdb->update(
            $wpdb->prefix . 'twss_issues',
            array('suggested_fix' => $suggested_fix),
            array(
                'scan_id' => $scan_id,
                'file_path' => $file_path
            )
        );
    }

    /**
     * Mark an issue as fixed
     *
     * @since    1.0.0
     * @param    int       $issue_id    The issue ID
     */
    public function mark_issue_as_fixed($issue_id)
    {
        global $wpdb;

        // Get the scan ID for this issue
        $scan_id = $wpdb->get_var($wpdb->prepare(
            "SELECT scan_id FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ));

        if ($scan_id) {
            // Update the issue
            $wpdb->update(
                $wpdb->prefix . 'twss_issues',
                array(
                    'status' => 'fixed',
                    'date_fixed' => current_time('mysql')
                ),
                array('id' => $issue_id)
            );

            // Update the issues_fixed count in the scans table
            $wpdb->query($wpdb->prepare(
                "UPDATE {$wpdb->prefix}twss_scans SET issues_fixed = issues_fixed + 1 WHERE id = %d",
                $scan_id
            ));
        }
    }

    /**
     * Get scan summary
     *
     * @since    1.0.0
     * @param    int      $scan_id    The scan ID
     * @return   array    Scan summary
     */
    public function get_scan_summary($scan_id)
    {
        global $wpdb;

        // Get scan details
        $scan = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_scans WHERE id = %d",
            $scan_id
        ), ARRAY_A);

        if (!$scan) {
            return false;
        }

        // Get issue counts by severity
        $issues_by_severity = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, COUNT(*) as count FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d GROUP BY severity",
            $scan_id
        ), ARRAY_A);

        $high_severity = 0;
        $medium_severity = 0;
        $low_severity = 0;

        foreach ($issues_by_severity as $row) {
            switch ($row['severity']) {
                case 'high':
                    $high_severity = $row['count'];
                    break;
                case 'medium':
                    $medium_severity = $row['count'];
                    break;
                case 'low':
                    $low_severity = $row['count'];
                    break;
            }
        }

        // Get the latest progress for each stage and overall current progress
        $current_progress = $wpdb->get_row($wpdb->prepare(
            "SELECT stage, progress, message FROM {$wpdb->prefix}twss_scan_progress 
             WHERE scan_id = %d 
             ORDER BY timestamp DESC 
             LIMIT 1",
            $scan_id
        ), ARRAY_A);

        $progress = $wpdb->get_results($wpdb->prepare(
            "SELECT stage, message FROM (
                SELECT stage, message, timestamp, 
                       ROW_NUMBER() OVER (PARTITION BY stage ORDER BY timestamp DESC) as rn
                FROM {$wpdb->prefix}twss_scan_progress
                WHERE scan_id = %d
            ) t WHERE rn = 1",
            $scan_id
        ), ARRAY_A);

        return array(
            'scan_id' => $scan_id,
            'scan_date' => $scan['scan_date'],
            'status' => $scan['status'],
            'total_files' => $scan['total_files'],
            'total_issues' => $scan['issues_found'],
            'issues_found' => $scan['issues_found'], // Alias for JavaScript compatibility
            'fixed_issues' => $scan['issues_fixed'],
            'high_severity' => $high_severity,
            'medium_severity' => $medium_severity,
            'low_severity' => $low_severity,
            'current_stage' => $current_progress ? $current_progress['stage'] : null,
            'progress' => $current_progress ? $current_progress['progress'] : 0,
            'message' => $current_progress ? $current_progress['message'] : 'Initializing scan...',
            'error_message' => $scan['error_message'],
            'stage_progress' => $progress
        );
    }

    /**
     * Get scan issues
     *
     * @since    1.0.0
     * @param    int       $scan_id    The scan ID
     * @param    string    $status     Optional status filter
     * @return   array     Array of issues
     */
    public function get_scan_issues($scan_id, $status = null)
    {
        global $wpdb;

        $query = "SELECT * FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d";
        $params = array($scan_id);

        if ($status !== null) {
            $query .= " AND status = %s";
            $params[] = $status;
        }

        $query .= " ORDER BY severity DESC, date_detected ASC";

        return $wpdb->get_results(
            $wpdb->prepare($query, $params),
            ARRAY_A
        );
    }

    /**
     * Get fixable issues
     *
     * @since    1.0.0
     * @param    int       $scan_id    The scan ID
     * @return   array     Array of fixable issues
     */
    public function get_fixable_issues($scan_id)
    {
        global $wpdb;

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues 
             WHERE scan_id = %d 
             AND status = 'confirmed' 
             AND suggested_fix IS NOT NULL
             AND suggested_fix != ''",
            $scan_id
        ), ARRAY_A);
    }

    /**
     * Add file to whitelist
     *
     * @since    1.0.0
     * @param    string    $file_path    Path to the file
     * @param    string    $reason       Reason for whitelisting
     * @return   bool      Success or failure
     */
    public function add_to_whitelist($file_path, $reason = '')
    {
        global $wpdb;

        $current_user = wp_get_current_user();
        $username = $current_user->user_login;

        return $wpdb->insert(
            $wpdb->prefix . 'twss_whitelist',
            array(
                'file_path' => $file_path,
                'reason' => $reason,
                'date_added' => current_time('mysql'),
                'added_by' => $username
            )
        );
    }

    /**
     * Check if file is whitelisted
     *
     * @since    1.0.0
     * @param    string    $file_path    Path to the file
     * @return   bool      True if whitelisted
     */
    public function is_file_whitelisted($file_path)
    {
        global $wpdb;

        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_whitelist WHERE file_path = %s",
            $file_path
        ));

        return ($count > 0);
    }

    /**
     * Get the last scan progress record
     *
     * @since    1.0.1
     * @param    int       $scan_id    The scan ID
     * @return   array|false    The last scan progress record or false
     */
    public function get_last_scan_progress($scan_id)
    {
        global $wpdb;

        $progress = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_scan_progress 
         WHERE scan_id = %d
         ORDER BY id DESC
         LIMIT 1",
            $scan_id
        ), ARRAY_A);

        return $progress;
    }

    /**
     * Clear all issues from database
     *
     * @since    1.0.2
     * @return   boolean   True on success, false on failure
     */
    public function clear_all_issues()
    {
        global $wpdb;

        $table_issues = $wpdb->prefix . 'twss_issues';
        $table_scans = $wpdb->prefix . 'twss_scans';
        $table_progress = $wpdb->prefix . 'twss_scan_progress';

        // Clear all issues
        $result1 = $wpdb->query("DELETE FROM $table_issues");

        // Clear all scans
        $result2 = $wpdb->query("DELETE FROM $table_scans");

        // Clear all scan progress
        $result3 = $wpdb->query("DELETE FROM $table_progress");

        return ($result1 !== false && $result2 !== false && $result3 !== false);
    }

    /**
     * Clear issues from a specific scan
     *
     * @since    1.0.2
     * @param    int       $scan_id    Scan ID
     * @return   boolean   True on success, false on failure
     */
    public function clear_scan_issues($scan_id)
    {
        global $wpdb;

        $table_issues = $wpdb->prefix . 'twss_issues';
        $table_progress = $wpdb->prefix . 'twss_scan_progress';

        // Clear issues for this scan
        $result1 = $wpdb->delete($table_issues, array('scan_id' => $scan_id), array('%d'));

        // Clear progress for this scan
        $result2 = $wpdb->delete($table_progress, array('scan_id' => $scan_id), array('%d'));

        // Update scan record to show 0 issues
        $this->update_scan_counts($scan_id, 0, 0);

        return ($result1 !== false && $result2 !== false);
    }

    /**
     * Update scan counts in the scans table
     *
     * @since    1.0.17
     * @param    int      $scan_id        The scan ID
     * @param    int      $issues_found   Number of issues found
     * @param    int      $issues_fixed   Number of issues fixed
     */
    public function update_scan_counts($scan_id, $issues_found, $issues_fixed)
    {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'twss_scans';

        $result = $wpdb->update(
            $table_scans,
            array(
                'issues_found' => $issues_found,
                'issues_fixed' => $issues_fixed
            ),
            array('id' => $scan_id),
            array('%d', '%d'),
            array('%d')
        );

        return $result !== false;
    }

    /**
     * Clean up ghost files from issues table
     * Removes issues for files that no longer exist
     *
     * @since    1.0.19
     * @return   int Number of ghost issues removed
     */
    public function cleanup_ghost_issues()
    {
        global $wpdb;

        $table_issues = $wpdb->prefix . 'twss_issues';

        // Get all issues that are not about missing files
        $issues = $wpdb->get_results(
            "SELECT id, file_path, issue_type FROM {$table_issues} 
             WHERE issue_type NOT IN ('core_file_missing', 'plugin_file_missing', 'theme_file_missing')
             AND status = 'pending'",
            ARRAY_A
        );

        $ghost_count = 0;
        $ghost_ids = array();

        foreach ($issues as $issue) {
            $file_path = $issue['file_path'];
            $realpath = realpath($file_path);

            // Check if file exists and is valid
            if (
                !file_exists($file_path) ||
                !is_file($file_path) ||
                !is_readable($file_path) ||
                $realpath === false ||
                !file_exists($realpath) ||
                filesize($file_path) === false ||
                filesize($file_path) <= 0
            ) {
                $ghost_ids[] = intval($issue['id']);
                $ghost_count++;
                error_log("TWSS: Found ghost issue for non-existent file: {$file_path} (Issue ID: {$issue['id']})");
            }
        }

        // Also check for ghost theme and plugin files specifically
        // Look for themes that don't exist on the system
        $theme_issues = $wpdb->get_results(
            "SELECT id, file_path, issue_type FROM {$table_issues}
             WHERE file_path LIKE '%/themes/%'
             AND status = 'pending'",
            ARRAY_A
        );

        foreach ($theme_issues as $issue) {
            $file_path = $issue['file_path'];

            // Extract theme name from path
            if (preg_match('#\/themes\/([^\/]+)#', $file_path, $matches)) {
                $theme_name = $matches[1];
                $theme_dir = get_theme_root() . '/' . $theme_name;

                // If theme directory doesn't exist, it's a ghost file
                if (!is_dir($theme_dir)) {
                    if (!in_array(intval($issue['id']), $ghost_ids)) {
                        $ghost_ids[] = intval($issue['id']);
                        $ghost_count++;
                        error_log("TWSS: Found ghost theme issue for non-existent theme: {$theme_name} (Issue ID: {$issue['id']})");
                    }
                }
            }
        }

        // Look for plugins that don't exist on the system
        $plugin_issues = $wpdb->get_results(
            "SELECT id, file_path, issue_type FROM {$table_issues}
             WHERE file_path LIKE '%/plugins/%'
             AND status = 'pending'",
            ARRAY_A
        );

        foreach ($plugin_issues as $issue) {
            $file_path = $issue['file_path'];

            // Extract plugin directory name from path
            if (preg_match('#\/plugins\/([^\/]+)#', $file_path, $matches)) {
                $plugin_dir = $matches[1];
                $full_plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_dir;

                // If plugin directory doesn't exist, it's a ghost file
                if (!is_dir($full_plugin_dir)) {
                    if (!in_array(intval($issue['id']), $ghost_ids)) {
                        $ghost_ids[] = intval($issue['id']);
                        $ghost_count++;
                        error_log("TWSS: Found ghost plugin issue for non-existent plugin: {$plugin_dir} (Issue ID: {$issue['id']})");
                    }
                }
            }
        }

        // Remove ghost issues in batches
        if (!empty($ghost_ids)) {
            $id_placeholders = implode(',', array_fill(0, count($ghost_ids), '%d'));
            $wpdb->query($wpdb->prepare(
                "DELETE FROM {$table_issues} WHERE id IN ({$id_placeholders})",
                ...$ghost_ids
            ));

            error_log("TWSS: Removed {$ghost_count} ghost issues from database");
        }

        return $ghost_count;
    }

    /**
     * Store comprehensive scan result for a file
     *
     * @since    1.0.29
     * @param    int       $scan_id           The scan ID
     * @param    string    $file_path         File path
     * @param    string    $file_content      File content for AI analysis
     * @param    array     $pattern_matches   Pattern matches found
     * @param    string    $scan_stage        Current scan stage
     * @return   int       Result record ID
     */
    public function store_scan_result($scan_id, $file_path, $file_content, $pattern_matches = array(), $scan_stage = 'unknown')
    {
        global $wpdb;

        $file_hash = hash('sha256', $file_content);

        $wpdb->insert(
            $wpdb->prefix . 'twss_scan_results',
            array(
                'scan_id' => $scan_id,
                'file_path' => $file_path,
                'file_size' => strlen($file_content),
                'file_hash' => $file_hash,
                'file_content' => $file_content,
                'pattern_matches' => json_encode($pattern_matches),
                'ai_analyzed' => 0,
                'ai_risk_score' => 0,
                'ai_threats' => '[]',
                'scan_stage' => $scan_stage,
                'timestamp' => current_time('mysql')
            )
        );

        return $wpdb->insert_id;
    }

    /**
     * Get files pending AI analysis for a scan
     *
     * @since    1.0.29
     * @param    int    $scan_id    The scan ID
     * @param    int    $limit      Limit number of results
     * @param    int    $offset     Offset for pagination
     * @return   array  Files pending AI analysis
     */
    public function get_files_pending_ai_analysis($scan_id, $limit = 10, $offset = 0)
    {
        global $wpdb;

        return $wpdb->get_results($wpdb->prepare(
            "SELECT id, file_path, file_content, pattern_matches FROM {$wpdb->prefix}twss_scan_results 
             WHERE scan_id = %d AND ai_analyzed = 0 
             ORDER BY id ASC LIMIT %d OFFSET %d",
            $scan_id,
            $limit,
            $offset
        ));
    }

    /**
     * Update AI analysis results for a file
     *
     * @since    1.0.29
     * @param    int       $scan_id           The scan ID
     * @param    string    $file_path         File path
     * @param    int       $risk_score        AI risk score (0-100)
     * @param    array     $threats           Detected threats
     * @return   bool      Success status
     */
    public function update_ai_analysis_result($scan_id, $file_path, $risk_score = 0, $threats = array())
    {
        global $wpdb;

        return $wpdb->update(
            $wpdb->prefix . 'twss_scan_results',
            array(
                'ai_analyzed' => 1,
                'ai_risk_score' => $risk_score,
                'ai_threats' => json_encode($threats)
            ),
            array(
                'scan_id' => $scan_id,
                'file_path' => $file_path
            ),
            array('%d', '%d', '%s'),
            array('%d', '%s')
        );
    }

    /**
     * Get comprehensive scan statistics including AI analysis
     *
     * @since    1.0.29
     * @param    int    $scan_id    The scan ID
     * @return   array  Comprehensive scan statistics
     */
    public function get_comprehensive_scan_stats($scan_id)
    {
        global $wpdb;

        $stats = array();

        // Total files scanned
        $stats['total_files'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_scan_results WHERE scan_id = %d",
            $scan_id
        ));

        // Files analyzed by AI
        $stats['ai_analyzed_files'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_scan_results WHERE scan_id = %d AND ai_analyzed = 1",
            $scan_id
        ));

        // High risk files (AI score > 70)
        $stats['high_risk_files'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_scan_results WHERE scan_id = %d AND ai_risk_score > 70",
            $scan_id
        ));

        // Files by scan stage
        $stage_stats = $wpdb->get_results($wpdb->prepare(
            "SELECT scan_stage, COUNT(*) as count FROM {$wpdb->prefix}twss_scan_results 
             WHERE scan_id = %d GROUP BY scan_stage",
            $scan_id
        ), ARRAY_A);

        $stats['files_by_stage'] = array();
        foreach ($stage_stats as $stage) {
            $stats['files_by_stage'][$stage['scan_stage']] = $stage['count'];
        }

        return $stats;
    }

    /**
     * Get recent scans for dashboard display
     *
     * @since    1.0.0
     * @param    int    $limit    Number of scans to retrieve
     * @return   array  Array of recent scans
     */
    public function get_recent_scans($limit = 5)
    {
        global $wpdb;

        if (!$this->validate_database_connection()) {
            return array();
        }

        $scans = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_scans 
             ORDER BY scan_date DESC 
             LIMIT %d",
            $limit
        ), ARRAY_A);

        return $scans ? $scans : array();
    }

    /**
     * Get dashboard statistics
     *
     * @since    1.0.0
     * @return   array  Dashboard statistics
     */
    public function get_dashboard_stats()
    {
        global $wpdb;

        if (!$this->validate_database_connection()) {
            return array(
                'total_scans' => 0,
                'total_files_scanned' => 0,
                'total_issues_found' => 0,
                'total_issues_fixed' => 0,
                'last_scan_date' => null
            );
        }

        $stats = array();

        // Total scans
        $stats['total_scans'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_scans"
        ) ?: 0;

        // Total files scanned
        $stats['total_files_scanned'] = $wpdb->get_var(
            "SELECT SUM(total_files) FROM {$wpdb->prefix}twss_scans"
        ) ?: 0;

        // Total issues found
        $stats['total_issues_found'] = $wpdb->get_var(
            "SELECT SUM(issues_found) FROM {$wpdb->prefix}twss_scans"
        ) ?: 0;

        // Total issues fixed
        $stats['total_issues_fixed'] = $wpdb->get_var(
            "SELECT SUM(issues_fixed) FROM {$wpdb->prefix}twss_scans"
        ) ?: 0;

        // Last scan date
        $stats['last_scan_date'] = $wpdb->get_var(
            "SELECT scan_date FROM {$wpdb->prefix}twss_scans ORDER BY scan_date DESC LIMIT 1"
        );

        return $stats;
    }

    /**
     * Get all issues for issues page display
     *
     * @since    1.0.0
     * @param    string $status   Filter by status
     * @param    int    $limit    Number of issues to retrieve
     * @param    int    $offset   Offset for pagination
     * @return   array  Array of issues
     */
    public function get_all_issues($status = null, $limit = 50, $offset = 0)
    {
        global $wpdb;

        if (!$this->validate_database_connection()) {
            return array();
        }

        $sql = "SELECT * FROM {$wpdb->prefix}twss_issues";
        $params = array();

        if ($status) {
            $sql .= " WHERE status = %s";
            $params[] = $status;
        }

        $sql .= " ORDER BY date_detected DESC";

        if ($limit > 0) {
            $sql .= " LIMIT %d OFFSET %d";
            $params[] = $limit;
            $params[] = $offset;
        }

        if (!empty($params)) {
            $issues = $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A);
        } else {
            $issues = $wpdb->get_results($sql, ARRAY_A);
        }

        return $issues ? $issues : array();
    }

    /**
     * Get issue count by status
     *
     * @since    1.0.0
     * @return   array  Issue counts by status
     */
    public function get_issue_counts()
    {
        global $wpdb;

        if (!$this->validate_database_connection()) {
            return array(
                'pending' => 0,
                'resolved' => 0,
                'whitelisted' => 0,
                'total' => 0
            );
        }

        $counts = $wpdb->get_results(
            "SELECT status, COUNT(*) as count FROM {$wpdb->prefix}twss_issues GROUP BY status",
            ARRAY_A
        );

        $result = array(
            'pending' => 0,
            'resolved' => 0,
            'whitelisted' => 0,
            'total' => 0
        );

        foreach ($counts as $count) {
            $result[$count['status']] = (int)$count['count'];
            $result['total'] += (int)$count['count'];
        }

        return $result;
    }

    /**
     * Test database connection
     *
     * @since    1.0.0
     * @return   array  Connection test result
     */
    public function test_database_connection()
    {
        global $wpdb;

        try {
            // Test basic connection
            $test = $wpdb->get_var("SELECT 1");

            if ($test !== '1') {
                return array(
                    'success' => false,
                    'message' => 'Database connection test failed: ' . $wpdb->last_error
                );
            }

            // Test table existence
            $tables_exist = $this->check_tables_exist();

            return array(
                'success' => true,
                'message' => 'Database connection successful',
                'tables_exist' => $tables_exist,
                'mysql_version' => $wpdb->get_var("SELECT VERSION()"),
                'table_prefix' => $wpdb->prefix
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => 'Database connection error: ' . $e->getMessage()
            );
        }
    }

    /**
     * Check if all required tables exist
     *
     * @since    1.0.0
     * @return   array  Table existence status
     */
    private function check_tables_exist()
    {
        global $wpdb;

        $required_tables = array(
            'scans' => $wpdb->prefix . 'twss_scans',
            'issues' => $wpdb->prefix . 'twss_issues',
            'progress' => $wpdb->prefix . 'twss_scan_progress',
            'whitelist' => $wpdb->prefix . 'twss_whitelist',
            'scan_results' => $wpdb->prefix . 'twss_scan_results'
        );

        $existing_tables = array();

        foreach ($required_tables as $key => $table_name) {
            $exists = $wpdb->get_var($wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            ));
            $existing_tables[$key] = ($exists === $table_name);
        }

        return $existing_tables;
    }
}
