<?php

/**
 * The Security-Hardened Admin functionality of the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 * @security   Enhanced with comprehensive input validation, CSRF protection, and capability checks
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
     * Security nonce action name
     *
     * @since    1.0.32
     * @access   private
     * @var      string    $nonce_action
     */
    private $nonce_action = 'themewire_security_admin_action';

    /**
     * Initialize the class with enhanced security validation.
     *
     * @since    1.0.0
     * @security Enhanced constructor with proper WordPress hook timing
     * @param    string    $plugin_name       The name of this plugin.
     * @param    string    $version           The version of this plugin.
     */
    public function __construct($plugin_name, $version)
    {
        // Security: Validate inputs
        if (!is_string($plugin_name) || empty(trim($plugin_name))) {
            throw new InvalidArgumentException('Plugin name must be a non-empty string');
        }

        if (!is_string($version) || empty(trim($version))) {
            throw new InvalidArgumentException('Version must be a non-empty string');
        }

        // Security: Sanitize inputs if WordPress functions are available
        if (function_exists('sanitize_text_field')) {
            $this->plugin_name = sanitize_text_field($plugin_name);
            $this->version = sanitize_text_field($version);
        } else {
            // Fallback sanitization if WordPress not fully loaded
            $this->plugin_name = preg_replace('/[^a-zA-Z0-9\-_]/', '', $plugin_name);
            $this->version = preg_replace('/[^0-9\.]/', '', $version);
        }

        // Initialize components (defer capability checks until WordPress is loaded)
        $this->initialize_components();
    }

    /**
     * Validate user permissions for admin operations.
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
     * Initialize plugin components with error handling.
     *
     * @since    1.0.32
     * @security Enhanced with proper error handling and validation
     */
    private function initialize_components()
    {
        try {
            $this->scanner = new Themewire_Security_Scanner();
            $this->database = new Themewire_Security_Database();
            $this->fixer = new Themewire_Security_Fixer();
            $this->scheduler = new Themewire_Security_Scheduler();
            $this->ai_analyzer = new Themewire_Security_AI_Analyzer();
        } catch (Exception $e) {
            error_log('TWSS Admin: Component initialization failed - ' . $e->getMessage());

            // Show admin notice for initialization failure
            add_action('admin_notices', function () use ($e) {
                $this->show_initialization_error($e->getMessage());
            });
        }
    }

    /**
     * Show initialization error notice.
     *
     * @since    1.0.32
     * @param    string    $message    Error message
     */
    private function show_initialization_error($message)
    {
        if (!$this->validate_user_permissions()) {
            return;
        }

        echo '<div class="notice notice-error"><p>';
        if (function_exists('esc_html__')) {
            echo '<strong>' . esc_html__('ThemeWire Security Error:', 'themewire-security') . '</strong> ';
            echo esc_html(sprintf(__('Plugin initialization failed: %s', 'themewire-security'), $message));
        } else {
            echo '<strong>ThemeWire Security Error:</strong> Plugin initialization failed: ' . esc_html($message);
        }
        echo '</p></div>';
    }
    /**
     * Validate admin request with comprehensive security checks.
     *
     * @since    1.0.32
     * @param    string    $action       Action being performed
     * @param    bool      $check_nonce  Whether to check nonce (default: true)
     * @return   bool      True if request is valid
     */
    private function validate_admin_request($action = '', $check_nonce = true)
    {
        // Security: Check user capabilities only if WordPress is loaded
        if (!$this->validate_user_permissions()) {
            if (function_exists('wp_die')) {
                wp_die(__('You do not have sufficient permissions to access this page.', 'themewire-security'));
            }
            return false;
        }

        // Security: Verify nonce if required
        if ($check_nonce && function_exists('wp_verify_nonce')) {
            $nonce = '';
            if (function_exists('sanitize_text_field')) {
                $nonce = isset($_POST['_wpnonce']) ? sanitize_text_field($_POST['_wpnonce']) : (isset($_GET['_wpnonce']) ? sanitize_text_field($_GET['_wpnonce']) : '');
            }

            $nonce_action = !empty($action) ? $this->nonce_action . '_' . $action : $this->nonce_action;

            if (!wp_verify_nonce($nonce, $nonce_action)) {
                if (function_exists('wp_die')) {
                    wp_die(__('Security check failed. Please try again.', 'themewire-security'));
                }
                return false;
            }
        }

        // Security: Check request method for state-changing operations
        if (!empty($action) && !in_array($_SERVER['REQUEST_METHOD'] ?? '', ['POST', 'GET'])) {
            if (function_exists('wp_die')) {
                wp_die(__('Invalid request method.', 'themewire-security'));
            }
            return false;
        }

        return true;
    }
    /**
     * Sanitize and validate input data.
     *
     * @since    1.0.32
     * @param    mixed     $data        Data to sanitize
     * @param    string    $type        Data type (text, email, url, int, array)
     * @param    array     $options     Additional options
     * @return   mixed     Sanitized data
     */
    private function sanitize_input($data, $type = 'text', $options = array())
    {
        if ($data === null) {
            return null;
        }

        switch ($type) {
            case 'text':
                return function_exists('sanitize_text_field') ? sanitize_text_field($data) : strip_tags($data);

            case 'textarea':
                return function_exists('sanitize_textarea_field') ? sanitize_textarea_field($data) : strip_tags($data);

            case 'email':
                if (function_exists('sanitize_email')) {
                    return sanitize_email($data);
                }
                return filter_var($data, FILTER_SANITIZE_EMAIL);

            case 'url':
                if (function_exists('esc_url_raw')) {
                    return esc_url_raw($data);
                }
                return filter_var($data, FILTER_SANITIZE_URL);

            case 'int':
                return intval($data);

            case 'float':
                return floatval($data);

            case 'bool':
                return (bool) $data;

            case 'array':
                if (!is_array($data)) {
                    return array();
                }

                $sanitized = array();
                $value_type = isset($options['value_type']) ? $options['value_type'] : 'text';

                foreach ($data as $key => $value) {
                    $clean_key = function_exists('sanitize_key') ? sanitize_key($key) : preg_replace('/[^a-z0-9_\-]/', '', strtolower($key));
                    $sanitized[$clean_key] = $this->sanitize_input($value, $value_type, $options);
                }

                return $sanitized;

            case 'key':
                return function_exists('sanitize_key') ? sanitize_key($data) : preg_replace('/[^a-z0-9_\-]/', '', strtolower($data));

            default:
                return function_exists('sanitize_text_field') ? sanitize_text_field($data) : strip_tags($data);
        }
    }

    /**
     * Register the stylesheets for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_styles()
    {
        if (!function_exists('get_current_screen') || !function_exists('wp_enqueue_style')) {
            return;
        }

        $screen = get_current_screen();

        if ($screen && strpos($screen->id, 'themewire-security') !== false) {
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
        if (
            !function_exists('get_current_screen') || !function_exists('wp_enqueue_script') ||
            !function_exists('wp_localize_script')
        ) {
            return;
        }

        $screen = get_current_screen();

        if ($screen && strpos($screen->id, 'themewire-security') !== false) {
            wp_enqueue_script($this->plugin_name, TWSS_PLUGIN_URL . 'admin/assets/js/themewire-security-admin.js', array('jquery'), $this->version, true);

            // Enqueue additional JavaScript for new features
            wp_enqueue_script($this->plugin_name . '-additional', TWSS_PLUGIN_URL . 'admin/assets/js/themewire-security-additional.js', array('jquery', $this->plugin_name), $this->version, true);

            // Get current scan ID if exists
            $current_scan_id = function_exists('get_option') ? get_option('twss_current_scan_id') : '';

            $ajax_data = array(
                'nonce' => function_exists('wp_create_nonce') ? wp_create_nonce('twss_nonce') : '',
                'scan_in_progress' => method_exists($this->scanner, 'is_scan_in_progress') ? $this->scanner->is_scan_in_progress() : false,
                'has_interrupted_scan' => !empty($current_scan_id),
                'current_scan_id' => $current_scan_id,
                'version' => $this->version,
                'has_update' => method_exists($this, 'has_update') ? $this->has_update() : false
            );

            // Add URLs if admin_url function is available
            if (function_exists('admin_url')) {
                $ajax_data['ajax_url'] = admin_url('admin-ajax.php');
                $ajax_data['admin_url'] = admin_url();
            }

            // Add scheduler info if available
            if (method_exists($this->scheduler, 'get_next_scan_time')) {
                $ajax_data['next_scan'] = $this->scheduler->get_next_scan_time();
            }

            // Add internationalization strings
            $ajax_data['i18n'] = array(
                'scanning' => function_exists('__') ? __('Scanning...', 'themewire-security') : 'Scanning...',
                'start_scan' => function_exists('__') ? __('Start Scan', 'themewire-security') : 'Start Scan',
                'resume_scan' => function_exists('__') ? __('Resume Scan', 'themewire-security') : 'Resume Scan',
                'testing' => function_exists('__') ? __('Testing...', 'themewire-security') : 'Testing...',
                'test_connection' => function_exists('__') ? __('Test Connection', 'themewire-security') : 'Test Connection'
            );

            wp_localize_script($this->plugin_name, 'twss_data', $ajax_data);
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
        $use_saved_key = isset($_POST['use_saved_key']) && $_POST['use_saved_key'] === 'true';

        // If using saved key flag, get the stored API key
        if ($use_saved_key || $api_key === 'USE_SAVED_KEY') {
            $api_key = get_option('twss_openai_api_key', '');
            if (empty($api_key)) {
                wp_send_json_error(__('No saved API key found. Please enter your API key first.', 'themewire-security'));
                return;
            }
        }

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
        $use_saved_key = isset($_POST['use_saved_key']) && $_POST['use_saved_key'] === 'true';

        // If using saved key flag, get the stored API key
        if ($use_saved_key || $api_key === 'USE_SAVED_KEY') {
            $api_key = get_option('twss_gemini_api_key', '');
            if (empty($api_key)) {
                wp_send_json_error(__('No saved API key found. Please enter your API key first.', 'themewire-security'));
                return;
            }
        }

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
     * AJAX handler for testing OpenRouter API key
     *
     * @since    1.0.1
     */
    public function ajax_test_openrouter_api()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
        }

        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';
        $use_saved_key = isset($_POST['use_saved_key']) && $_POST['use_saved_key'] === 'true';

        // If using saved key flag, get the stored API key
        if ($use_saved_key || $api_key === 'USE_SAVED_KEY') {
            $api_key = get_option('twss_openrouter_api_key', '');
            if (empty($api_key)) {
                wp_send_json_error(__('No saved API key found. Please enter your API key first.', 'themewire-security'));
                return;
            }
        }

        if (empty($api_key)) {
            wp_send_json_error(__('API key cannot be empty', 'themewire-security'));
        }

        $result = $this->ai_analyzer->test_openrouter_api_key($api_key);

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    /**
     * AJAX handler for testing Groq API key
     *
     * @since    1.0.31
     */
    public function ajax_test_groq_api()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action', 'themewire-security'));
            return;
        }

        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';
        $use_saved_key = isset($_POST['use_saved_key']) && $_POST['use_saved_key'] === 'true';

        // If using saved key flag, get the stored API key
        if ($use_saved_key || $api_key === 'USE_SAVED_KEY') {
            $api_key = get_option('twss_groq_api_key', '');
            if (empty($api_key)) {
                wp_send_json_error(__('No saved API key found. Please enter your API key first.', 'themewire-security'));
                return;
            }
        }

        if (empty($api_key)) {
            wp_send_json_error(__('API key is required', 'themewire-security'));
            return;
        }

        $result = $this->ai_analyzer->test_groq_api_key($api_key);

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
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
        // Prevent duplicate menu registration
        static $menu_added = false;
        if ($menu_added) {
            return;
        }
        $menu_added = true;

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
        register_setting('twss_settings', 'twss_openrouter_api_key');

        register_setting('twss_settings', 'twss_scheduled_time');
        register_setting('twss_settings', 'twss_auto_fix');
        register_setting('twss_settings', 'twss_ai_fix_aggressive');
        register_setting('twss_settings', 'twss_quarantine_threats');
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
        // Get the most recent scan for display purposes
        try {
            $database = new Themewire_Security_Database();
            $recent_scans = $database->get_recent_scans(1);
            $scan = !empty($recent_scans) ? $recent_scans[0] : null;
        } catch (Exception $e) {
            $scan = null;
        }

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

        // Use optimized scanning with real-time progress
        $result = $this->scanner->start_optimized_scan();

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

        // Get comprehensive scan status from scanner
        $status = $this->scanner->get_scan_status();

        // Additional cleanup: If no active scan found but scan_in_progress transient exists, clear it
        if (!$status['success'] && strpos($status['message'], 'No active scan found') !== false) {
            $scan_in_progress_transient = get_transient('twss_scan_in_progress');
            if ($scan_in_progress_transient === 'yes') {
                // Clear stale scan progress flag
                delete_transient('twss_scan_in_progress');
                delete_transient('twss_scan_last_activity');
                delete_transient('twss_optimized_scan_state');
                delete_transient('twss_chunked_scan_state');

                // Add info to debug data
                if (isset($status['debug'])) {
                    $status['debug']['cleaned_stale_transients'] = true;
                }
            }
        }

        if ($status['success']) {
            wp_send_json_success($status);
        } else {
            wp_send_json_error($status);
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

        // Check if we're using optimized scanning
        $optimized_state = get_transient('twss_optimized_scan_state');
        if ($optimized_state) {
            $result = $this->scanner->process_optimized_scan_chunk();
        } else {
            // Fallback to legacy chunked scanning
            $result = $this->scanner->process_scan_chunk();
        }

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
        if (
            strpos($error_message, 'quota') !== false ||
            strpos($error_message, 'rate limited') !== false ||
            strpos($error_message, 'temporarily unavailable') !== false ||
            strpos($error_message, 'RESOURCE_EXHAUSTED') !== false
        ) {

            return __('AI analysis service is temporarily unavailable due to high demand. The scanner is using pattern-based detection as a fallback. Please try again later for enhanced AI analysis.', 'themewire-security');
        }

        // Check for connection errors
        if (
            strpos($error_message, 'connection') !== false ||
            strpos($error_message, 'timeout') !== false ||
            strpos($error_message, 'network') !== false
        ) {

            return __('Network connectivity issue detected. Please check your internet connection and try again.', 'themewire-security');
        }

        // Check for authentication errors
        if (
            strpos($error_message, 'authentication') !== false ||
            strpos($error_message, 'API key') !== false ||
            strpos($error_message, 'unauthorized') !== false
        ) {

            return __('API authentication failed. Please check your API key settings in the plugin configuration.', 'themewire-security');
        }

        // Check for file system errors
        if (
            strpos($error_message, 'file') !== false &&
            (strpos($error_message, 'permission') !== false ||
                strpos($error_message, 'access') !== false)
        ) {

            return __('File access permission issue. Please check file permissions on your WordPress installation.', 'themewire-security');
        }

        // Generic fallback for unhandled errors (but don't expose technical details)
        return __('An unexpected error occurred during the security scan. Please try again or contact support if the issue persists.', 'themewire-security');
    }

    /**
     * AJAX handler for toggling global auto-fix mode
     *
     * @since    1.0.52
     */
    public function ajax_toggle_auto_fix()
    {
        check_ajax_referer('twss_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action', 'themewire-security')));
        }

        $enabled = isset($_POST['enabled']) ? intval($_POST['enabled']) : 0;

        $result = update_option('twss_auto_fix', (bool)$enabled);

        if ($result !== false) {
            wp_send_json_success(array(
                'message' => $enabled
                    ? __('AI Auto-Fix Mode enabled successfully', 'themewire-security')
                    : __('AI Auto-Fix Mode disabled successfully', 'themewire-security'),
                'enabled' => (bool)$enabled
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to update auto-fix setting', 'themewire-security')));
        }
    }
}
