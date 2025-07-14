<?php
/**
 * The core plugin class.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security {

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
    public function __construct() {
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
    private function load_dependencies() {
        // Core loader
        require_once TWSS_PLUGIN_DIR . 'includes/class-loader.php';
        
        // Internationalization
        require_once TWSS_PLUGIN_DIR . 'includes/class-i18n.php';
        
        // Admin area
        require_once TWSS_PLUGIN_DIR . 'admin/class-admin.php';
        
        // Scanner functionality
        require_once TWSS_PLUGIN_DIR . 'includes/class-scanner.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-ai-analyzer.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-fixer.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-scheduler.php';
        require_once TWSS_PLUGIN_DIR . 'includes/class-database.php';

        $this->loader = new Themewire_Security_Loader();
    }

    /**
     * Define the locale for internationalization.
     *
     * @since    1.0.0
     * @access   private
     */
    private function set_locale() {
        $plugin_i18n = new Themewire_Security_i18n();
        $this->loader->add_action('plugins_loaded', $plugin_i18n, 'load_plugin_textdomain');
    }

    /**
     * Register all of the hooks related to the admin area.
     *
     * @since    1.0.0
     * @access   private
     */
    private function define_admin_hooks() {
        $plugin_admin = new Themewire_Security_Admin($this->get_plugin_name(), $this->get_version());
        
        // Admin scripts and styles
        $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_styles');
        $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_scripts');
        
        // Admin menu
        $this->loader->add_action('admin_menu', $plugin_admin, 'add_plugin_admin_menu');
        
        // Settings
        $this->loader->add_action('admin_init', $plugin_admin, 'register_settings');
        
        // Ajax handlers
        $this->loader->add_action('wp_ajax_twss_start_scan', $plugin_admin, 'ajax_start_scan');
        $this->loader->add_action('wp_ajax_twss_get_scan_status', $plugin_admin, 'ajax_get_scan_status');
        $this->loader->add_action('wp_ajax_twss_fix_issue', $plugin_admin, 'ajax_fix_issue');
        $this->loader->add_action('wp_ajax_twss_quarantine_file', $plugin_admin, 'ajax_quarantine_file');
        $this->loader->add_action('wp_ajax_twss_whitelist_file', $plugin_admin, 'ajax_whitelist_file');
        $this->loader->add_action('wp_ajax_twss_delete_file', $plugin_admin, 'ajax_delete_file');
    }

    /**
     * Register all of the hooks related to the scanner functionality.
     *
     * @since    1.0.0
     * @access   private
     */
    private function define_scanner_hooks() {
        $plugin_scanner = new Themewire_Security_Scanner();
        $plugin_scheduler = new Themewire_Security_Scheduler();
        
        // Schedule daily scans
        $this->loader->add_action('twss_daily_scan', $plugin_scanner, 'run_scheduled_scan');
        $this->loader->add_action('admin_init', $plugin_scheduler, 'register_scan_schedule');
    }

    /**
     * Run the loader to execute all hooks.
     *
     * @since    1.0.0
     */
    public function run() {
        $this->loader->run();
    }

    /**
     * The name of the plugin used to uniquely identify it.
     *
     * @since     1.0.0
     * @return    string    The name of the plugin.
     */
    public function get_plugin_name() {
        return $this->plugin_name;
    }

    /**
     * The reference to the class that orchestrates the hooks.
     *
     * @since     1.0.0
     * @return    Themewire_Security_Loader    Orchestrates the hooks of the plugin.
     */
    public function get_loader() {
        return $this->loader;
    }

    /**
     * Retrieve the version number of the plugin.
     *
     * @since     1.0.0
     * @return    string    The version number of the plugin.
     */
    public function get_version() {
        return $this->version;
    }
}