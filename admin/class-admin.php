<?php

/**
 * The admin-specific functionality of the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Admin
{

    /**
     * The ID of this plugin.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $plugin_name    The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $version    The current version of this plugin.
     */
    private $version;

    /**
     * Scanner instance
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Scanner    $scanner
     */
    private $scanner;

    /**
     * Database instance
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Database    $database
     */
    private $database;

    /**
     * Fixer instance
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Fixer    $fixer
     */
    private $fixer;

    /**
     * Scheduler instance
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_Scheduler    $scheduler
     */
    private $scheduler;

    /**
     * AI Analyzer instance
     *
     * @since    1.0.0
     * @access   private
     * @var      Themewire_Security_AI_Analyzer    $ai_analyzer
     */
    private $ai_analyzer;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     * @param    string    $plugin_name       The name of this plugin.
     * @param    string    $version           The version of this plugin.
     */
    public function __construct($plugin_name, $version)
    {
        $this->plugin_name = $plugin_name;
        $this->version = $version;

        $this->scanner = new Themewire_Security_Scanner();
        $this->database = new Themewire_Security_Database();
        $this->fixer = new Themewire_Security_Fixer();
        $this->scheduler = new Themewire_Security_Scheduler();
        $this->ai_analyzer = new Themewire_Security_AI_Analyzer();

        // AJAX handlers are now registered in the main plugin class
    }

    /**
     * Register the stylesheets for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_styles()
    {
        $screen = get_current_screen();

        if (strpos($screen->id, 'themewire-security') !== false) {
            wp_enqueue_style($this->plugin_name, TWSS_PLUGIN_URL . 'admin/assets/css/themewire-security-admin.css', array(), $this->version);
        }
    }

    /**
     * Register the JavaScript for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_scripts()
    {
        $screen = get_current_screen();

        if (strpos($screen->id, 'themewire-security') !== false) {
            wp_enqueue_script($this->plugin_name, TWSS_PLUGIN_URL . 'admin/assets/js/themewire-security-admin.js', array('jquery'), $this->version, true);

            // Enqueue additional JavaScript for new features
            wp_enqueue_script($this->plugin_name . '-additional', TWSS_PLUGIN_URL . 'admin/assets/js/themewire-security-additional.js', array('jquery', $this->plugin_name), $this->version, true);

            // Get current scan ID if exists
            $current_scan_id = get_option('twss_current_scan_id');

            wp_localize_script($this->plugin_name, 'twss_data', array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'admin_url' => admin_url(),
                'nonce' => wp_create_nonce('twss_nonce'),
                'scan_in_progress' => $this->scanner->is_scan_in_progress(),
                'has_interrupted_scan' => !empty($current_scan_id),
                'current_scan_id' => $current_scan_id,
                'next_scan' => $this->scheduler->get_next_scan_time(),
                'version' => $this->version,
                'has_update' => $this->has_update(),
                'i18n' => array(
                    'scanning' => __('Scanning...', 'themewire-security'),
                    'start_scan' => __('Start Scan', 'themewire-security'),
                    'resume_scan' => __('Resume Scan', 'themewire-security'),
                    'testing' => __('Testing...', 'themewire-security'),
                    'test_connection' => __('Test Connection', 'themewire-security')
                )
            ));
        }
    }

    // Add these new methods to the admin class

    /**
     * AJAX handler for resuming a scan
     *
     * @since    1.0.1
     */
    public function ajax_resume_scan()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $result = $this->scanner->resume_scan();

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for testing OpenAI API key
     *
     * @since    1.0.1
     */
    public function ajax_test_openai_api()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';

        if (empty($api_key)) {
            wp_send_json_error(__('API key cannot be empty', 'themewire-security'));
        }

        $result = $this->ai_analyzer->test_openai_api_key($api_key);

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for testing Gemini API key
     *
     * @since    1.0.1
     */
    public function ajax_test_gemini_api()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';

        if (empty($api_key)) {
            wp_send_json_error(__('API key cannot be empty', 'themewire-security'));
        }

        $result = $this->ai_analyzer->test_gemini_api_key($api_key);

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for disconnecting OAuth
     *
     * @since    1.0.2
     */
    public function ajax_disconnect_oauth()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $provider = isset($_POST['provider']) ? sanitize_text_field($_POST['provider']) : '';

        if (!in_array($provider, ['openai', 'gemini'])) {
            wp_send_json_error(__('Invalid provider', 'themewire-security'));
        }

        // Clear the OAuth token
        if ($provider === 'openai') {
            delete_option('twss_openai_oauth_token');
        } else {
            delete_option('twss_gemini_oauth_token');
        }

        wp_send_json_success(array(
            'message' => sprintf(__('Successfully disconnected from %s', 'themewire-security'), ucfirst($provider))
        ));
    }

    /**
     * AJAX handler for bulk file actions
     *
     * @since    1.0.2
     */
    public function ajax_bulk_file_action()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $bulk_action = isset($_POST['bulk_action']) ? sanitize_text_field($_POST['bulk_action']) : '';
        $files = isset($_POST['files']) ? array_map('intval', $_POST['files']) : array();

        if (empty($bulk_action) || empty($files)) {
            wp_send_json_error(__('Invalid request parameters', 'themewire-security'));
        }

        if (!in_array($bulk_action, ['fix', 'quarantine', 'delete', 'whitelist'])) {
            wp_send_json_error(__('Invalid bulk action', 'themewire-security'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'twss_issues';

        $success_count = 0;
        $error_count = 0;
        $results = array();

        foreach ($files as $issue_id) {
            // Get the issue details
            $issue = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$table_name} WHERE id = %d",
                $issue_id
            ), ARRAY_A);

            if (!$issue) {
                $error_count++;
                continue;
            }

            try {
                switch ($bulk_action) {
                    case 'fix':
                        $result = $this->fixer->fix_issue($issue_id);
                        break;
                    case 'quarantine':
                        $result = $this->fixer->quarantine_file($issue['file_path']);
                        break;
                    case 'delete':
                        $result = $this->fixer->delete_file($issue['file_path']);
                        break;
                    case 'whitelist':
                        $result = $this->fixer->whitelist_file($issue['file_path']);
                        break;
                }

                if ($result && isset($result['success']) && $result['success']) {
                    $success_count++;
                    // Update issue status
                    $wpdb->update(
                        $table_name,
                        array('status' => $bulk_action === 'whitelist' ? 'whitelisted' : 'resolved'),
                        array('id' => $issue_id),
                        array('%s'),
                        array('%d')
                    );
                } else {
                    $error_count++;
                }
            } catch (Exception $e) {
                $error_count++;
                $results[] = sprintf(
                    __('Error processing %s: %s', 'themewire-security'),
                    basename($issue['file_path']),
                    $e->getMessage()
                );
            }
        }

        $message = sprintf(
            __('Processed %d files successfully, %d errors', 'themewire-security'),
            $success_count,
            $error_count
        );

        if ($error_count > 0) {
            $message .= '. ' . __('Some files could not be processed.', 'themewire-security');
        }

        wp_send_json_success(array(
            'message' => $message,
            'success_count' => $success_count,
            'error_count' => $error_count,
            'details' => $results
        ));
    }

    /**
     * Add plugin admin menu
     *
     * @since    1.0.0
     */
    public function add_plugin_admin_menu()
    {
        // Main menu
        add_menu_page(
            __('Themewire AI Security', 'themewire-security'),
            __('Security AI', 'themewire-security'),
            'manage_options',
            'themewire-security',
            array($this, 'display_plugin_dashboard'),
            'dashicons-shield',
            81
        );

        // Dashboard submenu
        add_submenu_page(
            'themewire-security',
            __('Dashboard', 'themewire-security'),
            __('Dashboard', 'themewire-security'),
            'manage_options',
            'themewire-security',
            array($this, 'display_plugin_dashboard')
        );

        // Scan submenu
        add_submenu_page(
            'themewire-security',
            __('Scan', 'themewire-security'),
            __('Scan', 'themewire-security'),
            'manage_options',
            'themewire-security-scan',
            array($this, 'display_scan_page')
        );

        // Issues submenu
        add_submenu_page(
            'themewire-security',
            __('Issues', 'themewire-security'),
            __('Issues', 'themewire-security'),
            'manage_options',
            'themewire-security-issues',
            array($this, 'display_issues_page')
        );

        // Settings submenu
        add_submenu_page(
            'themewire-security',
            __('Settings', 'themewire-security'),
            __('Settings', 'themewire-security'),
            'manage_options',
            'themewire-security-settings',
            array($this, 'display_settings_page')
        );

        // Version submenu
        add_submenu_page(
            'themewire-security',
            __('Version', 'themewire-security'),
            $this->has_update() ? sprintf(__('Version %s', 'themewire-security'), '<span class="update-plugins count-1"><span class="update-count">1</span></span>') : __('Version', 'themewire-security'),
            'manage_options',
            'themewire-security-version',
            array($this, 'display_version_page')
        );

        // OAuth callback page (hidden from menu)
        add_submenu_page(
            null, // Parent slug null makes it hidden from menu
            __('OAuth Callback', 'themewire-security'),
            __('OAuth Callback', 'themewire-security'),
            'manage_options',
            'themewire-security-oauth-callback',
            array($this, 'handle_oauth_callback')
        );
    }

    /**
     * Check if plugin has an update available
     * 
     * @since    1.0.0
     * @return   boolean   True if update available
     */
    private function has_update()
    {
        $update_data = get_site_transient('update_plugins');

        if (isset($update_data->response[TWSS_PLUGIN_BASENAME])) {
            return true;
        }

        return false;
    }

    /**
     * Register plugin settings
     *
     * @since    1.0.0
     */
    public function register_settings()
    {
        register_setting('twss_settings', 'twss_ai_provider');
        register_setting('twss_settings', 'twss_openai_api_key');
        register_setting('twss_settings', 'twss_gemini_api_key');

        // OAuth settings for API providers
        register_setting('twss_settings', 'twss_openai_client_id');
        register_setting('twss_settings', 'twss_openai_client_secret');
        register_setting('twss_settings', 'twss_gemini_client_id');
        register_setting('twss_settings', 'twss_gemini_client_secret');

        register_setting('twss_settings', 'twss_scheduled_time');
        register_setting('twss_settings', 'twss_auto_fix');
        register_setting('twss_settings', 'twss_send_email');
        register_setting('twss_settings', 'twss_remove_data_on_uninstall');
        register_setting('twss_settings', 'twss_auto_update');
    }

    /**
     * Display the dashboard page
     *
     * @since    1.0.0
     */
    public function display_plugin_dashboard()
    {
        require_once TWSS_PLUGIN_DIR . 'admin/views/dashboard.php';
    }

    /**
     * Display the scan page
     *
     * @since    1.0.0
     */
    public function display_scan_page()
    {
        require_once TWSS_PLUGIN_DIR . 'admin/views/scan.php';
    }

    /**
     * Display the issues page
     *
     * @since    1.0.0
     */
    public function display_issues_page()
    {
        require_once TWSS_PLUGIN_DIR . 'admin/views/issues.php';
    }

    /**
     * Display the settings page
     *
     * @since    1.0.0
     */
    public function display_settings_page()
    {
        require_once TWSS_PLUGIN_DIR . 'admin/views/settings.php';
    }

    /**
     * Display the version page
     *
     * @since    1.0.0
     */
    public function display_version_page()
    {
        require_once TWSS_PLUGIN_DIR . 'admin/views/version.php';
    }

    /**
     * AJAX handler for starting a scan
     *
     * @since    1.0.0
     */
    public function ajax_start_scan()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        // Use chunked scanning to prevent timeouts
        $result = $this->scanner->start_chunked_scan();

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            // Sanitize error message before sending to user
            if (isset($result['message'])) {
                $result['message'] = $this->sanitize_error_message($result['message']);
            }
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for getting scan status
     *
     * @since    1.0.0
     */
    public function ajax_get_scan_status()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $scan_id = isset($_POST['scan_id']) ? intval($_POST['scan_id']) : null;

        // If no scan_id provided, try to get the current scan ID
        if (!$scan_id) {
            $scan_id = get_option('twss_current_scan_id');
        }

        if (!$scan_id) {
            wp_send_json_error(__('No scan in progress', 'themewire-security'));
        }

        $scan_status = $this->database->get_scan_summary($scan_id);

        if ($scan_status) {
            wp_send_json_success($scan_status);
        } else {
            wp_send_json_error(__('Scan not found', 'themewire-security'));
        }
    }

    /**
     * AJAX handler for processing a scan chunk
     *
     * @since    1.0.23
     */
    public function ajax_process_scan_chunk()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $result = $this->scanner->process_scan_chunk();

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for fixing an issue
     *
     * @since    1.0.0
     */
    public function ajax_fix_issue()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;

        if (!$issue_id) {
            wp_send_json_error(__('Invalid issue ID', 'themewire-security'));
        }

        $result = $this->fixer->fix_issue_by_id($issue_id);

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for quarantining a file
     *
     * @since    1.0.0
     */
    public function ajax_quarantine_file()
    {
        // Add debugging
        error_log('TWSS: ajax_quarantine_file called');
        error_log('TWSS: POST data: ' . print_r($_POST, true));

        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            error_log('TWSS: Permission denied for user');
            wp_send_json_error(array('message' => __('You do not have permission to perform this action', 'themewire-security')));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;

        if (!$issue_id) {
            error_log('TWSS: Invalid issue ID: ' . $issue_id);
            wp_send_json_error(array('message' => __('Invalid issue ID', 'themewire-security')));
        }

        global $wpdb;
        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ), ARRAY_A);

        if (!$issue) {
            error_log('TWSS: Issue not found for ID: ' . $issue_id);
            wp_send_json_error(array('message' => __('Issue not found', 'themewire-security')));
        }

        error_log('TWSS: Found issue: ' . print_r($issue, true));

        $result = $this->fixer->quarantine_file($issue['scan_id'], $issue['file_path']);

        error_log('TWSS: Quarantine result: ' . print_r($result, true));

        if ($result['success']) {
            $this->database->mark_issue_as_fixed($issue_id);
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for whitelisting a file
     *
     * @since    1.0.0
     */
    public function ajax_whitelist_file()
    {
        // Add debugging
        error_log('TWSS: ajax_whitelist_file called');
        error_log('TWSS: POST data: ' . print_r($_POST, true));

        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            error_log('TWSS: Permission denied for user');
            wp_send_json_error(array('message' => __('You do not have permission to perform this action', 'themewire-security')));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;
        $reason = isset($_POST['reason']) ? sanitize_text_field($_POST['reason']) : '';

        if (!$issue_id) {
            error_log('TWSS: Invalid issue ID: ' . $issue_id);
            wp_send_json_error(array('message' => __('Invalid issue ID', 'themewire-security')));
        }

        global $wpdb;
        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ), ARRAY_A);

        if (!$issue) {
            error_log('TWSS: Issue not found for ID: ' . $issue_id);
            wp_send_json_error(array('message' => __('Issue not found', 'themewire-security')));
        }

        error_log('TWSS: Found issue: ' . print_r($issue, true));

        $result = $this->database->add_to_whitelist($issue['file_path'], $reason);

        error_log('TWSS: Whitelist result: ' . ($result ? 'success' : 'failed'));

        if ($result) {
            $this->database->update_issue_status($issue['scan_id'], $issue['file_path'], 'whitelisted');
            wp_send_json_success(array(
                'success' => true,
                'message' => __('File added to whitelist', 'themewire-security')
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to add file to whitelist', 'themewire-security')));
        }
    }

    /**
     * AJAX handler for deleting a file
     *
     * @since    1.0.0
     */
    public function ajax_delete_file()
    {
        // Add debugging
        error_log('TWSS: ajax_delete_file called');
        error_log('TWSS: POST data: ' . print_r($_POST, true));

        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            error_log('TWSS: Permission denied for user');
            wp_send_json_error(array('message' => __('You do not have permission to perform this action', 'themewire-security')));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;

        if (!$issue_id) {
            error_log('TWSS: Invalid issue ID: ' . $issue_id);
            wp_send_json_error(array('message' => __('Invalid issue ID', 'themewire-security')));
        }

        global $wpdb;
        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ), ARRAY_A);

        if (!$issue) {
            error_log('TWSS: Issue not found for ID: ' . $issue_id);
            wp_send_json_error(array('message' => __('Issue not found', 'themewire-security')));
        }

        error_log('TWSS: Found issue: ' . print_r($issue, true));

        $result = $this->fixer->delete_file($issue['scan_id'], $issue['file_path']);

        error_log('TWSS: Delete result: ' . print_r($result, true));

        if ($result['success']) {
            $this->database->mark_issue_as_fixed($issue_id);
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for restoring WordPress core files
     *
     * @since    1.0.2
     */
    public function ajax_restore_core_file()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;

        if (!$issue_id) {
            wp_send_json_error(__('Invalid issue ID', 'themewire-security'));
        }

        global $wpdb;
        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ), ARRAY_A);

        if (!$issue) {
            wp_send_json_error(__('Issue not found', 'themewire-security'));
        }

        $result = $this->fixer->restore_core_file($issue['scan_id'], $issue['file_path']);

        if ($result['success']) {
            $this->database->mark_issue_as_fixed($issue_id);
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for testing AJAX functionality
     *
     * @since    1.0.2
     */
    public function ajax_test_connection()
    {
        error_log('TWSS: ajax_test_connection called');

        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Permission denied'));
        }

        wp_send_json_success(array('message' => 'AJAX connection successful!'));
    }

    /**
     * AJAX handler for analyzing an individual issue with AI
     *
     * @since    1.0.0
     */
    public function ajax_analyze_issue()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;

        if (!$issue_id) {
            wp_send_json_error(__('Invalid issue ID', 'themewire-security'));
        }

        // Get the issue from database
        global $wpdb;
        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_issues WHERE id = %d",
            $issue_id
        ), ARRAY_A);

        if (!$issue) {
            wp_send_json_error(__('Issue not found', 'themewire-security'));
        }

        // Check if file still exists
        if (!file_exists($issue['file_path'])) {
            wp_send_json_error(__('File no longer exists', 'themewire-security'));
        }

        // Initialize the AI analyzer
        $ai_analyzer = new Themewire_Security_AI_Analyzer();

        try {
            // Run AI analysis on the file
            $analysis_result = $ai_analyzer->analyze_file($issue['file_path']);

            if ($analysis_result && $analysis_result['success']) {
                // Update the issue with AI analysis
                $updated = $wpdb->update(
                    $wpdb->prefix . 'twss_issues',
                    array(
                        'ai_analysis' => json_encode($analysis_result['analysis'])
                    ),
                    array('id' => $issue_id),
                    array('%s'),
                    array('%d')
                );

                if ($updated !== false) {
                    wp_send_json_success(array(
                        'message' => __('AI analysis completed successfully', 'themewire-security'),
                        'analysis' => $analysis_result['analysis']
                    ));
                } else {
                    wp_send_json_error(__('Failed to save AI analysis to database', 'themewire-security'));
                }
            } else {
                $error_message = isset($analysis_result['message']) ? $analysis_result['message'] : __('AI analysis failed', 'themewire-security');
                wp_send_json_error($error_message);
            }
        } catch (Exception $e) {
            error_log('TWSS AI Analysis Error: ' . $e->getMessage());
            $sanitized_message = $this->sanitize_error_message($e->getMessage());
            wp_send_json_error($sanitized_message);
        }
    }

    /**
     * Handle OAuth callback from authentication providers
     *
     * @since    1.0.2
     */
    public function handle_oauth_callback()
    {
        // Verify nonce for security
        if (!isset($_GET['state']) || !wp_verify_nonce($_GET['state'], 'openai_oauth_state') && !wp_verify_nonce($_GET['state'], 'gemini_oauth_state')) {
            wp_die(__('Invalid authentication state. Please try again.', 'themewire-security'));
        }

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to access this page.', 'themewire-security'));
        }

        // Check for authorization code
        if (!isset($_GET['code'])) {
            wp_die(__('Authorization failed. No authorization code received.', 'themewire-security'));
        }

        $auth_code = sanitize_text_field($_GET['code']);
        $state = sanitize_text_field($_GET['state']);

        // Determine which provider this is for
        $is_openai = wp_verify_nonce($state, 'openai_oauth_state');
        $is_gemini = wp_verify_nonce($state, 'gemini_oauth_state');

        if ($is_openai) {
            $result = $this->process_openai_oauth_callback($auth_code);
            $provider = 'OpenAI';
        } elseif ($is_gemini) {
            $result = $this->process_gemini_oauth_callback($auth_code);
            $provider = 'Google/Gemini';
        } else {
            wp_die(__('Invalid authentication provider.', 'themewire-security'));
        }

        // Redirect with results
        if ($result['success']) {
            $redirect_url = admin_url('admin.php?page=themewire-security-settings&oauth_success=1&provider=' . urlencode($provider));
        } else {
            $redirect_url = admin_url('admin.php?page=themewire-security-settings&oauth_error=1&message=' . urlencode($result['message']));
        }

        wp_redirect($redirect_url);
        exit;
    }

    /**
     * Process OpenAI OAuth callback
     *
     * @since    1.0.2
     * @param    string    $auth_code    Authorization code from OAuth provider
     * @return   array     Result array with success status and message
     */
    private function process_openai_oauth_callback($auth_code)
    {
        // Exchange authorization code for access token
        $client_id = get_option('twss_openai_client_id', '');
        $client_secret = get_option('twss_openai_client_secret', '');
        $redirect_uri = admin_url('admin.php?page=themewire-security-oauth-callback');

        if (empty($client_id) || empty($client_secret)) {
            return array(
                'success' => false,
                'message' => __('OpenAI OAuth credentials not configured. Please contact your administrator.', 'themewire-security')
            );
        }

        $token_url = 'https://api.openai.com/v1/oauth/token';
        $post_data = array(
            'grant_type' => 'authorization_code',
            'code' => $auth_code,
            'redirect_uri' => $redirect_uri,
            'client_id' => $client_id,
            'client_secret' => $client_secret
        );

        $response = wp_remote_post($token_url, array(
            'body' => $post_data,
            'headers' => array(
                'Content-Type' => 'application/x-www-form-urlencoded'
            ),
            'timeout' => 30
        ));

        if (is_wp_error($response)) {
            return array(
                'success' => false,
                'message' => __('Failed to connect to OpenAI. Please try again.', 'themewire-security')
            );
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $response_body = wp_remote_retrieve_body($response);

        if ($response_code !== 200) {
            return array(
                'success' => false,
                'message' => __('OpenAI authentication failed. Please check your credentials.', 'themewire-security')
            );
        }

        $token_data = json_decode($response_body, true);
        if (!$token_data || !isset($token_data['access_token'])) {
            return array(
                'success' => false,
                'message' => __('Invalid token response from OpenAI.', 'themewire-security')
            );
        }

        // Store the access token securely
        update_option('twss_openai_oauth_token', $token_data['access_token']);
        if (isset($token_data['refresh_token'])) {
            update_option('twss_openai_refresh_token', $token_data['refresh_token']);
        }
        if (isset($token_data['expires_in'])) {
            update_option('twss_openai_token_expires', time() + intval($token_data['expires_in']));
        }

        return array(
            'success' => true,
            'message' => __('Successfully connected to OpenAI!', 'themewire-security')
        );
    }

    /**
     * Process Google/Gemini OAuth callback
     *
     * @since    1.0.2
     * @param    string    $auth_code    Authorization code from OAuth provider
     * @return   array     Result array with success status and message
     */
    private function process_gemini_oauth_callback($auth_code)
    {
        // Exchange authorization code for access token
        $client_id = get_option('twss_gemini_client_id', '');
        $client_secret = get_option('twss_gemini_client_secret', '');
        $redirect_uri = admin_url('admin.php?page=themewire-security-oauth-callback');

        if (empty($client_id) || empty($client_secret)) {
            return array(
                'success' => false,
                'message' => __('Google OAuth credentials not configured. Please contact your administrator.', 'themewire-security')
            );
        }

        $token_url = 'https://oauth2.googleapis.com/token';
        $post_data = array(
            'grant_type' => 'authorization_code',
            'code' => $auth_code,
            'redirect_uri' => $redirect_uri,
            'client_id' => $client_id,
            'client_secret' => $client_secret
        );

        $response = wp_remote_post($token_url, array(
            'body' => $post_data,
            'headers' => array(
                'Content-Type' => 'application/x-www-form-urlencoded'
            ),
            'timeout' => 30
        ));

        if (is_wp_error($response)) {
            return array(
                'success' => false,
                'message' => __('Failed to connect to Google. Please try again.', 'themewire-security')
            );
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $response_body = wp_remote_retrieve_body($response);

        if ($response_code !== 200) {
            return array(
                'success' => false,
                'message' => __('Google authentication failed. Please check your credentials.', 'themewire-security')
            );
        }

        $token_data = json_decode($response_body, true);
        if (!$token_data || !isset($token_data['access_token'])) {
            return array(
                'success' => false,
                'message' => __('Invalid token response from Google.', 'themewire-security')
            );
        }

        // Store the access token securely
        update_option('twss_gemini_oauth_token', $token_data['access_token']);
        if (isset($token_data['refresh_token'])) {
            update_option('twss_gemini_refresh_token', $token_data['refresh_token']);
        }
        if (isset($token_data['expires_in'])) {
            update_option('twss_gemini_token_expires', time() + intval($token_data['expires_in']));
        }

        return array(
            'success' => true,
            'message' => __('Successfully connected to Google/Gemini!', 'themewire-security')
        );
    }

    /**
     * AJAX handler for getting OAuth URL
     *
     * @since    1.0.2
     */
    public function ajax_get_oauth_url()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $provider = sanitize_text_field($_POST['provider']);

        if (!in_array($provider, array('openai', 'gemini'))) {
            wp_send_json_error(__('Invalid provider', 'themewire-security'));
        }

        $ai_analyzer = new Themewire_Security_AI_Analyzer();

        if ($provider === 'openai') {
            $oauth_url = $ai_analyzer->get_openai_oauth_url();
        } else {
            $oauth_url = $ai_analyzer->get_gemini_oauth_url();
        }

        if ($oauth_url === false) {
            wp_send_json_error(__('OAuth credentials not configured. Please contact your administrator.', 'themewire-security'));
        }

        wp_send_json_success(array('url' => $oauth_url));
    }

    /**
     * AJAX handler for stopping scan
     *
     * @since    1.0.2
     */
    public function ajax_stop_scan()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $result = $this->scanner->stop_scan();

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for clearing all issues
     *
     * @since    1.0.2
     */
    public function ajax_clear_all_issues()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $result = $this->database->clear_all_issues();

        if ($result) {
            // Also clear scan state options
            delete_option('twss_current_scan_id');

            // Clear any scan-related transients
            $this->scanner->clear_scan_checkpoints();

            wp_send_json_success(array(
                'message' => __('All issues and scan history cleared successfully', 'themewire-security')
            ));
        } else {
            wp_send_json_error(array(
                'message' => __('Error clearing issues. Please try again.', 'themewire-security')
            ));
        }
    }

    /**
     * AJAX handler for clearing issues from specific scan
     *
     * @since    1.0.2
     */
    public function ajax_clear_scan_issues()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $scan_id = intval($_POST['scan_id']);

        if (empty($scan_id)) {
            wp_send_json_error(__('Invalid scan ID', 'themewire-security'));
        }

        $result = $this->database->clear_scan_issues($scan_id);

        if ($result) {
            wp_send_json_success(array(
                'message' => __('Scan issues cleared successfully', 'themewire-security')
            ));
        } else {
            wp_send_json_error(array(
                'message' => __('Error clearing scan issues. Please try again.', 'themewire-security')
            ));
        }
    }

    /**
     * AJAX handler for cleaning up ghost files from issues table
     *
     * @since    1.0.21
     */
    public function ajax_cleanup_ghost_files()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $ghost_count = $this->database->cleanup_ghost_issues();

        wp_send_json_success(array(
            'message' => sprintf(
                __('Cleaned up %d ghost files from scan results', 'themewire-security'),
                $ghost_count
            ),
            'ghost_count' => $ghost_count
        ));
    }

    /**
     * Sanitize error messages for user display
     * 
     * @since    1.0.27
     * @param    string    $error_message    Raw error message
     * @return   string    Sanitized user-friendly message
     */
    private function sanitize_error_message($error_message)
    {
        // Check for API quota/rate limiting errors
        if (strpos($error_message, 'quota') !== false || 
            strpos($error_message, 'rate limited') !== false || 
            strpos($error_message, 'temporarily unavailable') !== false ||
            strpos($error_message, 'RESOURCE_EXHAUSTED') !== false) {
            
            return __('AI analysis service is temporarily unavailable due to high demand. The scanner is using pattern-based detection as a fallback. Please try again later for enhanced AI analysis.', 'themewire-security');
        }
        
        // Check for connection errors
        if (strpos($error_message, 'connection') !== false || 
            strpos($error_message, 'timeout') !== false ||
            strpos($error_message, 'network') !== false) {
            
            return __('Network connectivity issue detected. Please check your internet connection and try again.', 'themewire-security');
        }
        
        // Check for authentication errors
        if (strpos($error_message, 'authentication') !== false || 
            strpos($error_message, 'API key') !== false ||
            strpos($error_message, 'unauthorized') !== false) {
            
            return __('API authentication failed. Please check your API key settings in the plugin configuration.', 'themewire-security');
        }
        
        // Check for file system errors
        if (strpos($error_message, 'file') !== false && 
            (strpos($error_message, 'permission') !== false || 
             strpos($error_message, 'access') !== false)) {
            
            return __('File access permission issue. Please check file permissions on your WordPress installation.', 'themewire-security');
        }
        
        // Generic fallback for unhandled errors (but don't expose technical details)
        return __('An unexpected error occurred during the security scan. Please try again or contact support if the issue persists.', 'themewire-security');
    }
}
