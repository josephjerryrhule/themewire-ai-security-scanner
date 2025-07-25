<?php

/**
 * Plugin Name: Themewire AI Security Scanner
 * Plugin URI: https://github.com/josephjerryrhule/themewire-ai-security-scanner
 * Description: Advanced AI-powered WordPress security scanner with automatic malware detection, intelligent patching, and real-time threat remediation. Features comprehensive scanning, AI-enhanced auto-fix capabilities, and production-grade security hardening using multiple AI providers (OpenAI, Gemini, OpenRouter, GroqCloud).
 * Version: 1.0.53
 * Author: Themewire
 * Author URI: https://themewire.co
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: themewire-security
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 5.6
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

//Define plugin constants
define('THEMEWIRE_SECURITY_VERSION', '1.0.50');
define('TWSS_VERSION', '1.0.53');
define('TWSS_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('TWSS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('TWSS_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('TWSS_GITHUB_USERNAME', 'josephjerryrhule');
define('TWSS_GITHUB_REPO', 'themewire-ai-security-scanner');

/**
 * The code that runs during plugin activation.
 */
function activate_themewire_security_scanner()
{
    try {
        require_once TWSS_PLUGIN_DIR . 'includes/class-activator.php';
        Themewire_Security_Activator::activate();
    } catch (Exception $e) {
        wp_die('Plugin activation failed: ' . $e->getMessage());
    }
}

/**
 * The code that runs during plugin deactivation.
 */
function deactivate_themewire_security_scanner()
{
    try {
        require_once TWSS_PLUGIN_DIR . 'includes/class-deactivator.php';
        Themewire_Security_Deactivator::deactivate();
    } catch (Exception $e) {
        error_log('Plugin deactivation error: ' . $e->getMessage());
    }
}

register_activation_hook(__FILE__, 'activate_themewire_security_scanner');
register_deactivation_hook(__FILE__, 'deactivate_themewire_security_scanner');

/**
 * Initialize GitHub updater.
 */
if (is_admin()) {
    try {
        require_once TWSS_PLUGIN_DIR . 'includes/class-github-updater.php';

        // Only initialize if the class exists and we're in admin
        if (class_exists('Themewire_Security_GitHub_Updater')) {
            $updater = new Themewire_Security_GitHub_Updater(
                __FILE__,
                TWSS_GITHUB_USERNAME . '/' . TWSS_GITHUB_REPO,
                TWSS_VERSION
            );
        }
    } catch (Exception $e) {
        // Fail silently for updater issues - don't break the plugin
        error_log('Themewire Security GitHub Updater error: ' . $e->getMessage());
    }
}

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require_once TWSS_PLUGIN_DIR . 'includes/class-themewire-security.php';

/**
 * Begins execution of the plugin.
 */
function run_themewire_security_scanner()
{
    // Prevent multiple instances
    static $plugin_instance = null;
    if ($plugin_instance !== null) {
        return;
    }

    try {
        $plugin_instance = new Themewire_Security();
        $plugin_instance->run();
    } catch (Exception $e) {
        error_log('Themewire Security Scanner error: ' . $e->getMessage());

        if (is_admin()) {
            add_action('admin_notices', function () use ($e) {
                echo '<div class="notice notice-error"><p>Themewire Security Scanner encountered an error: ' . esc_html($e->getMessage()) . '</p></div>';
            });
        }
    }
}

run_themewire_security_scanner();

// Debug functionality - remove in production
if (defined('WP_DEBUG') && WP_DEBUG) {
    require_once TWSS_PLUGIN_DIR . 'debug-admin-test.php';
}
