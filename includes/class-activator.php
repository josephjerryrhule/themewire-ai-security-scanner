<?php
/**
 * Fired during plugin activation.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Activator {

    /**
     * Plugin activation.
     *
     * @since    1.0.0
     */
    public static function activate() {
        // Create database tables
        require_once TWSS_PLUGIN_DIR . 'includes/class-database.php';
        $database = new Themewire_Security_Database();
        $database->create_tables();
        
        // Set default options
        if (!get_option('twss_ai_provider')) {
            update_option('twss_ai_provider', 'openai');
        }
        
        if (!get_option('twss_scheduled_time')) {
            update_option('twss_scheduled_time', '02:00');
        }
        
        if (!get_option('twss_auto_fix')) {
            update_option('twss_auto_fix', false);
        }
        
        if (!get_option('twss_send_email')) {
            update_option('twss_send_email', true);
        }
        
        // Schedule first scan
        require_once TWSS_PLUGIN_DIR . 'includes/class-scheduler.php';
        $scheduler = new Themewire_Security_Scheduler();
        $scheduler->register_scan_schedule();
        
        // Create necessary directories
        $upload_dir = wp_upload_dir();
        $quarantine_dir = $upload_dir['basedir'] . '/themewire-security-quarantine';
        
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
            
            // Add index.php to prevent directory listing
            file_put_contents($quarantine_dir . '/index.php', '<?php // Silence is golden');
            
            // Add .htaccess to prevent access to files
            file_put_contents($quarantine_dir . '/.htaccess', 'Deny from all');
        }
    }
}