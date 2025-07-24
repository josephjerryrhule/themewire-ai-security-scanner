<?php

/**
 * The core plugin class.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security
{

    /**
     * The loader that's responsible for maintaining and registering all hooks.
     *
     * @since    1.0.0
     * @access   protected
     * @var      Themewire_Security_Loader    $loader
     */
    protected $loader;

    /**
     * The unique identifier of this plugin.
     *
     * @since    1.0.0
     * @access   protected
     * @var      string    $plugin_name
     */
    protected $plugin_name = 'themewire-security';

    /**
     * The current version of the plugin.
     *
     * @since    1.0.0
     * @access   protected
     * @var      string    $version
     */
    protected $version;

    /**
     * Define the core functionality of the plugin.
     *
     * @since    1.0.0
     */
    public function __construct()
    {
        if (defined('TWSS_VERSION')) {
            $this->version = TWSS_VERSION;
        } else {
            $this->version = '1.0.0';
        }

        $this->load_dependencies();
        $this->set_locale();
        $this->define_admin_hooks();
        $this->define_scanner_hooks();
    }

    /**
     * Load the required dependencies for this plugin.
     *
     * @since    1.0.0
     * @access   private
     */
    private function load_dependencies()
    {
        // Core loader
        require_once TWSS_PLUGIN_DIR . 'includes/class-loader.php';

        // Internationalization
        require_once TWSS_PLUGIN_DIR . 'includes/class-i18n.php';

        // Admin area
        require_once TWSS_PLUGIN_DIR . 'admin/class-admin.php';

        // Utility classes
        require_once TWSS_PLUGIN_DIR . 'includes/class-logger.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-rate-limiter.php';

        // Scanner functionality
        require_once TWSS_PLUGIN_DIR . 'includes/class-scanner.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-ai-analyzer.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-fixer.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-scheduler.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-database.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-real-time-protection.php';

        $this->loader = new Themewire_Security_Loader();
    }

    /**
     * Define the locale for internationalization.
     *
     * @since    1.0.0
     * @access   private
     */
    private function set_locale()
    {
        $plugin_i18n = new Themewire_Security_i18n();
        $this->loader->add_action('plugins_loaded', $plugin_i18n, 'load_plugin_textdomain');
    }

    /**
     * Register all of the hooks related to the admin area.
     *
     * @since    1.0.0
     * @access   private
     */
    private function define_admin_hooks()
    {
        $plugin_admin = new Themewire_Security_Admin($this->get_plugin_name(), $this->get_version());

        // Admin scripts and styles
        $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_styles');
        $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_scripts');

        // Admin menu
        $this->loader->add_action('admin_menu', $plugin_admin, 'add_plugin_admin_menu');

        // Settings
        $this->loader->add_action('admin_init', $plugin_admin, 'register_settings');

        // Ajax handlers - using add_action directly to ensure they work
        add_action('wp_ajax_twss_start_scan', array($plugin_admin, 'ajax_start_scan'));
        add_action('wp_ajax_twss_resume_scan', array($plugin_admin, 'ajax_resume_scan'));
        add_action('wp_ajax_twss_stop_scan', array($plugin_admin, 'ajax_stop_scan'));
        add_action('wp_ajax_twss_get_scan_status', array($plugin_admin, 'ajax_get_scan_status'));
        add_action('wp_ajax_twss_process_scan_chunk', array($plugin_admin, 'ajax_process_scan_chunk'));
        add_action('wp_ajax_twss_fix_issue', array($plugin_admin, 'ajax_fix_issue'));
        add_action('wp_ajax_twss_quarantine_file', array($plugin_admin, 'ajax_quarantine_file'));
        add_action('wp_ajax_twss_whitelist_file', array($plugin_admin, 'ajax_whitelist_file'));
        add_action('wp_ajax_twss_delete_file', array($plugin_admin, 'ajax_delete_file'));
        add_action('wp_ajax_twss_test_openai_api', array($plugin_admin, 'ajax_test_openai_api'));
        add_action('wp_ajax_twss_test_gemini_api', array($plugin_admin, 'ajax_test_gemini_api'));
        add_action('wp_ajax_twss_test_openrouter_api', array($plugin_admin, 'ajax_test_openrouter_api'));
        add_action('wp_ajax_twss_test_groq_api', array($plugin_admin, 'ajax_test_groq_api'));
        add_action('wp_ajax_twss_clear_all_issues', array($plugin_admin, 'ajax_clear_all_issues'));
        add_action('wp_ajax_twss_clear_scan_issues', array($plugin_admin, 'ajax_clear_scan_issues'));
        add_action('wp_ajax_twss_bulk_file_action', array($plugin_admin, 'ajax_bulk_file_action'));
        add_action('wp_ajax_twss_restore_core_file', array($plugin_admin, 'ajax_restore_core_file'));
        add_action('wp_ajax_twss_test_connection', array($plugin_admin, 'ajax_test_connection'));
        add_action('wp_ajax_twss_analyze_issue', array($plugin_admin, 'ajax_analyze_issue'));
        add_action('wp_ajax_twss_cleanup_ghost_files', array($plugin_admin, 'ajax_cleanup_ghost_files'));
        add_action('wp_ajax_twss_toggle_auto_fix', array($plugin_admin, 'ajax_toggle_auto_fix'));

        // Debug: Log that handlers are registered
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('TWSS: AJAX handlers registered');
        }
    }

    /**
     * Register all of the hooks related to the scanner functionality.
     *
     * @since    1.0.0
     * @access   private
     */
    private function define_scanner_hooks()
    {
        $plugin_scanner = new Themewire_Security_Scanner();
        $plugin_scheduler = new Themewire_Security_Scheduler();

        // Schedule daily scans
        $this->loader->add_action('twss_daily_scan', $plugin_scanner, 'run_scheduled_scan');
        $this->loader->add_action('admin_init', $plugin_scheduler, 'register_scan_schedule');
    }

    /**
     * Register all of the hooks related to real-time protection.
     *
     * @since    1.0.52
     * @access   private
     */
    private function define_realtime_protection_hooks()
    {
        // Only enable real-time protection if enabled in settings
        $enable_realtime = get_option('twss_enable_realtime_protection', false);

        if ($enable_realtime) {
            $realtime_protection = new Themewire_Security_Real_Time_Protection();
            $realtime_protection->init();
        }
    }

    /**
     * Run the loader to execute all hooks.
     *
     * @since    1.0.0
     */
    public function run()
    {
        $this->set_locale();
        $this->define_admin_hooks();
        $this->define_scanner_hooks();
        $this->define_realtime_protection_hooks();

        $this->loader->run();
    }

    /**
     * The name of the plugin used to uniquely identify it.
     *
     * @since     1.0.0
     * @return    string    The name of the plugin.
     */
    public function get_plugin_name()
    {
        return $this->plugin_name;
    }

    /**
     * The reference to the class that orchestrates the hooks.
     *
     * @since     1.0.0
     * @return    Themewire_Security_Loader    Orchestrates the hooks of the plugin.
     */
    public function get_loader()
    {
        return $this->loader;
    }

    /**
     * Retrieve the version number of the plugin.
     *
     * @since     1.0.0
     * @return    string    The version number of the plugin.
     */
    public function get_version()
    {
        return $this->version;
    }
}
