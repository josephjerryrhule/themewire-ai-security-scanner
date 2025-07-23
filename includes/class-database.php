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
        // Create tables if they don't exist
        add_action('plugins_loaded', array($this, 'create_tables'));
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

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql_scans);
        dbDelta($sql_issues);
        dbDelta($sql_progress);
        dbDelta($sql_whitelist);
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
}
