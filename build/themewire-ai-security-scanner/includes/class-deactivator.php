<?php
/**
 * Fired during plugin deactivation.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Deactivator {

    /**
     * Plugin deactivation.
     *
     * @since    1.0.0
     */
    public static function deactivate() {
        // Clear scheduled events
        $timestamp = wp_next_scheduled('twss_daily_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'twss_daily_scan');
        }
        
        // Don't remove options or database tables to preserve settings and scan history
    }
}