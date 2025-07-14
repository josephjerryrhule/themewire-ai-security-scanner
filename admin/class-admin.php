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

        // Register AJAX handlers
        add_action('wp_ajax_twss_start_scan', array($this, 'ajax_start_scan'));
        add_action('wp_ajax_twss_resume_scan', array($this, 'ajax_resume_scan'));
        add_action('wp_ajax_twss_get_scan_status', array($this, 'ajax_get_scan_status'));
        add_action('wp_ajax_twss_fix_issue', array($this, 'ajax_fix_issue'));
        add_action('wp_ajax_twss_quarantine_file', array($this, 'ajax_quarantine_file'));
        add_action('wp_ajax_twss_whitelist_file', array($this, 'ajax_whitelist_file'));
        add_action('wp_ajax_twss_delete_file', array($this, 'ajax_delete_file'));
        add_action('wp_ajax_twss_test_openai_api', array($this, 'ajax_test_openai_api'));
        add_action('wp_ajax_twss_test_gemini_api', array($this, 'ajax_test_gemini_api'));
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

        $result = $this->scanner->start_scan();

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
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

        if (!$scan_id) {
            wp_send_json_error(__('Invalid scan ID', 'themewire-security'));
        }

        $scan_status = $this->database->get_scan_summary($scan_id);

        if ($scan_status) {
            wp_send_json_success($scan_status);
        } else {
            wp_send_json_error(__('Scan not found', 'themewire-security'));
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

        $result = $this->fixer->quarantine_file($issue['scan_id'], $issue['file_path']);

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
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $issue_id = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : null;
        $reason = isset($_POST['reason']) ? sanitize_text_field($_POST['reason']) : '';

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

        $result = $this->database->add_to_whitelist($issue['file_path'], $reason);

        if ($result) {
            $this->database->update_issue_status($issue['scan_id'], $issue['file_path'], 'whitelisted');
            wp_send_json_success(array(
                'success' => true,
                'message' => __('File added to whitelist', 'themewire-security')
            ));
        } else {
            wp_send_json_error(__('Failed to add file to whitelist', 'themewire-security'));
        }
    }

    /**
     * AJAX handler for deleting a file
     *
     * @since    1.0.0
     */
    public function ajax_delete_file()
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

        $result = $this->fixer->delete_file($issue['scan_id'], $issue['file_path']);

        if ($result['success']) {
            $this->database->mark_issue_as_fixed($issue_id);
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
}
