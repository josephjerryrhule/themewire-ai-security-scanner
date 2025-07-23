<?php

/**
 * Logger functionality for the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.2
 *
 * @package    Themewire_Security
 */

class Themewire_Security_Logger
{
    /**
     * Log directory
     *
     * @since    1.0.2
     * @access   private
     * @var      string    $log_dir
     */
    private $log_dir;

    /**
     * Log file path
     *
     * @since    1.0.2
     * @access   private
     * @var      string    $log_file
     */
    private $log_file;

    /**
     * Log levels
     */
    const LEVEL_ERROR = 'ERROR';
    const LEVEL_WARNING = 'WARNING';
    const LEVEL_INFO = 'INFO';
    const LEVEL_DEBUG = 'DEBUG';

    /**
     * Initialize the logger
     *
     * @since    1.0.2
     */
    public function __construct()
    {
        $upload_dir = wp_upload_dir();
        $this->log_dir = $upload_dir['basedir'] . '/themewire-security-logs';
        $this->log_file = $this->log_dir . '/security-' . date('Y-m-d') . '.log';

        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
            file_put_contents($this->log_dir . '/index.php', '<?php // Silence is golden');
            file_put_contents($this->log_dir . '/.htaccess', 'Deny from all');
        }
    }

    /**
     * Log an info message
     *
     * @since    1.0.2
     * @param    string    $message    Log message
     * @param    array     $context    Additional context
     */
    public function info($message, $context = array())
    {
        $this->log(self::LEVEL_INFO, $message, $context);
    }

    /**
     * Log a warning message
     *
     * @since    1.0.2
     * @param    string    $message    Log message
     * @param    array     $context    Additional context
     */
    public function warning($message, $context = array())
    {
        $this->log(self::LEVEL_WARNING, $message, $context);
    }

    /**
     * Log an error message
     *
     * @since    1.0.2
     * @param    string    $message    Log message
     * @param    array     $context    Additional context
     */
    public function error($message, $context = array())
    {
        $this->log(self::LEVEL_ERROR, $message, $context);
    }

    /**
     * Log a debug message
     *
     * @since    1.0.2
     * @param    string    $message    Log message
     * @param    array     $context    Additional context
     */
    public function debug($message, $context = array())
    {
        // Only log debug messages if WP_DEBUG is enabled
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->log(self::LEVEL_DEBUG, $message, $context);
        }
    }

    /**
     * Write log entry
     *
     * @since    1.0.2
     * @param    string    $level      Log level
     * @param    string    $message    Log message
     * @param    array     $context    Additional context
     */
    private function log($level, $message, $context = array())
    {
        $timestamp = current_time('Y-m-d H:i:s');
        $context_str = !empty($context) ? ' - Context: ' . json_encode($context) : '';

        $log_entry = sprintf(
            "[%s] [%s] %s%s" . PHP_EOL,
            $timestamp,
            strtoupper($level),
            $message,
            $context_str
        );

        // Write to file
        @file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);

        // Also write to WordPress error log if WP_DEBUG_LOG is enabled
        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG && in_array($level, array(self::LEVEL_ERROR, self::LEVEL_WARNING))) {
            error_log('Themewire Security: ' . $message . $context_str);
        }
    }

    /**
     * Get recent log entries
     *
     * @since    1.0.2
     * @param    int       $lines    Number of lines to retrieve
     * @return   array     Array of log entries
     */
    public function get_recent_logs($lines = 100)
    {
        if (!file_exists($this->log_file)) {
            return array();
        }

        $log_content = file_get_contents($this->log_file);
        $log_lines = explode("\n", $log_content);

        // Get the last $lines entries
        $recent_logs = array_slice($log_lines, -$lines);

        // Remove empty lines
        return array_filter($recent_logs);
    }

    /**
     * Clear log file
     *
     * @since    1.0.2
     * @return   boolean   True on success, false on failure
     */
    public function clear_logs()
    {
        if (file_exists($this->log_file)) {
            return @unlink($this->log_file);
        }
        return true;
    }
}
