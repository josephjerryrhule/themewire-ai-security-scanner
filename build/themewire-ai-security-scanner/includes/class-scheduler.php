<?php
/**
 * Scheduler functionality for automated scans.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Scheduler {

    /**
     * Initialize the class
     *
     * @since    1.0.0
     */
    public function __construct() {
        // Nothing to initialize
    }

    /**
     * Register the scheduled event for daily scans
     *
     * @since    1.0.0
     */
    public function register_scan_schedule() {
        if (!wp_next_scheduled('twss_daily_scan')) {
            $scheduled_time = get_option('twss_scheduled_time', '02:00');
            list($hour, $minute) = explode(':', $scheduled_time);
            
            // Convert to timestamp
            $timestamp = strtotime("today {$hour}:{$minute}");
            
            // If time has passed for today, schedule for tomorrow
            if ($timestamp < time()) {
                $timestamp = strtotime("tomorrow {$hour}:{$minute}");
            }
            
            wp_schedule_event($timestamp, 'daily', 'twss_daily_scan');
        }
    }

    /**
     * Update scheduled scan time
     *
     * @since    1.0.0
     * @param    string    $time    Time in 24-hour format (HH:MM)
     */
    public function update_scheduled_time($time) {
        // Validate time format
        if (!preg_match('/^([01]?[0-9]|2[0-3]):([0-5][0-9])$/', $time)) {
            return false;
        }
        
        // Clear existing schedule
        $timestamp = wp_next_scheduled('twss_daily_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'twss_daily_scan');
        }
        
        // Update option
        update_option('twss_scheduled_time', $time);
        
        // Set new schedule
        $this->register_scan_schedule();
        
        return true;
    }

    /**
     * Get next scheduled scan time
     *
     * @since    1.0.0
     * @return   string    Next scan time in format "YYYY-MM-DD HH:MM:SS" or false if no scan scheduled
     */
    public function get_next_scan_time() {
        $timestamp = wp_next_scheduled('twss_daily_scan');
        
        if ($timestamp) {
            return date('Y-m-d H:i:s', $timestamp);
        }
        
        return false;
    }
}