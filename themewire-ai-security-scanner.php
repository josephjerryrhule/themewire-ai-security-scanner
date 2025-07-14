<?php

/**
 * Plugin Name: Themewire AI Security Scanner
 * Plugin URI: https://github.com/josephjerryrhule/themewire-ai-security-scanner
 * Description: AI-powered WordPress security scanner that detects, fixes, and quarantines malware and security vulnerabilities.
 * Version: 1.0.1
 * Author: Themewire LTD
 * Author URI: https://themewire.co
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: themewire-security
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 5.6
 * Build Date: <?php echo date('Y-m-d', filectime(__FILE__)); ?>
 * Last Modified: <?php echo date('Y-m-d H:i:s', filemtime(__FILE__)); ?>
 * Modified By: Themewire LTD
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('TWSS_VERSION', '1.0.1');
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
    require_once TWSS_PLUGIN_DIR . 'includes/class-activator.php';
    Themewire_Security_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 */
function deactivate_themewire_security_scanner()
{
    require_once TWSS_PLUGIN_DIR . 'includes/class-deactivator.php';
    Themewire_Security_Deactivator::deactivate();
}

register_activation_hook(__FILE__, 'activate_themewire_security_scanner');
register_deactivation_hook(__FILE__, 'deactivate_themewire_security_scanner');

/**
 * Initialize GitHub updater.
 */
require_once TWSS_PLUGIN_DIR . 'includes/class-github-updater.php';

// Only initialize GitHub updater in admin area
if (is_admin()) {
    $updater = new Themewire_Security_GitHub_Updater(
        TWSS_GITHUB_USERNAME,
        TWSS_GITHUB_REPO,
        __FILE__
    );
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
    $plugin = new Themewire_Security();
    $plugin->run();
}

run_themewire_security_scanner();
