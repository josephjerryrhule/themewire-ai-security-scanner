<?php

/**
 * Rate limiting functionality for API calls.
 *
 * @link       https://themewire.com
 * @since      1.0.2
 * @package    Themewire_Security
 */

class Themewire_Security_Rate_Limiter
{

    private $limits = array(
        'openai' => array('requests' => 50, 'window' => 3600), // 50 requests per hour
        'gemini' => array('requests' => 100, 'window' => 3600) // 100 requests per hour
    );

    /**
     * Rate limit settings
     */
    const DEFAULT_REQUESTS_PER_MINUTE = 20;
    const DEFAULT_REQUESTS_PER_HOUR = 500;
    const DEFAULT_BURST_LIMIT = 5;

    /**
     * Initialize the rate limiter
     *
     * @since    1.0.2
     */
    public function __construct()
    {
        // Nothing to initialize
    }

    /**
     * Check if a request is allowed
     *
     * @since    1.0.2
     * @param    string    $key           Unique key for rate limiting
     * @param    int       $limit         Requests per minute limit
     * @param    int       $window        Time window in seconds
     * @return   boolean   True if request is allowed, false otherwise
     */
    public function is_allowed($key, $limit = self::DEFAULT_REQUESTS_PER_MINUTE, $window = 60)
    {
        $cache_key = 'twss_rate_limit_' . md5($key);
        $current_time = time();

        // Get current request data
        $request_data = get_transient($cache_key);

        if ($request_data === false) {
            // First request - allow it
            $request_data = array(
                'count' => 1,
                'window_start' => $current_time
            );
            set_transient($cache_key, $request_data, $window);
            return true;
        }

        // Check if we're still within the same time window
        if (($current_time - $request_data['window_start']) >= $window) {
            // New time window - reset counter
            $request_data = array(
                'count' => 1,
                'window_start' => $current_time
            );
            set_transient($cache_key, $request_data, $window);
            return true;
        }

        // Check if we've exceeded the limit
        if ($request_data['count'] >= $limit) {
            return false;
        }

        // Increment counter and allow request
        $request_data['count']++;
        set_transient($cache_key, $request_data, $window);
        return true;
    }

    /**
     * Get remaining requests for a key
     *
     * @since    1.0.2
     * @param    string    $key           Unique key for rate limiting
     * @param    int       $limit         Requests per minute limit
     * @param    int       $window        Time window in seconds
     * @return   int       Number of remaining requests
     */
    public function get_remaining_requests($key, $limit = self::DEFAULT_REQUESTS_PER_MINUTE, $window = 60)
    {
        $cache_key = 'twss_rate_limit_' . md5($key);
        $current_time = time();

        $request_data = get_transient($cache_key);

        if ($request_data === false) {
            return $limit;
        }

        // Check if we're in a new time window
        if (($current_time - $request_data['window_start']) >= $window) {
            return $limit;
        }

        return max(0, $limit - $request_data['count']);
    }

    /**
     * Get time until rate limit resets
     *
     * @since    1.0.2
     * @param    string    $key           Unique key for rate limiting
     * @param    int       $window        Time window in seconds
     * @return   int       Seconds until reset
     */
    public function get_reset_time($key, $window = 60)
    {
        $cache_key = 'twss_rate_limit_' . md5($key);
        $current_time = time();

        $request_data = get_transient($cache_key);

        if ($request_data === false) {
            return 0;
        }

        $window_end = $request_data['window_start'] + $window;
        return max(0, $window_end - $current_time);
    }

    /**
     * Add delay for burst protection
     *
     * @since    1.0.2
     * @param    string    $key           Unique key for rate limiting
     * @param    int       $burst_limit   Maximum burst requests
     * @return   int       Delay in seconds
     */
    public function get_burst_delay($key, $burst_limit = self::DEFAULT_BURST_LIMIT)
    {
        $burst_key = 'twss_burst_' . md5($key);
        $current_time = time();

        $burst_data = get_transient($burst_key);

        if ($burst_data === false) {
            // First request in burst
            set_transient($burst_key, array('count' => 1, 'start' => $current_time), 60);
            return 0;
        }

        // Check if burst window has expired (60 seconds)
        if (($current_time - $burst_data['start']) >= 60) {
            // Reset burst counter
            set_transient($burst_key, array('count' => 1, 'start' => $current_time), 60);
            return 0;
        }

        $burst_data['count']++;
        set_transient($burst_key, $burst_data, 60);

        // Apply progressive delay for burst protection
        if ($burst_data['count'] > $burst_limit) {
            $excess = $burst_data['count'] - $burst_limit;
            return min(10, $excess); // Max 10 seconds delay
        }

        return 0;
    }

    /**
     * Clear rate limit for a key
     *
     * @since    1.0.2
     * @param    string    $key    Unique key for rate limiting
     */
    public function clear_limit($key)
    {
        $cache_key = 'twss_rate_limit_' . md5($key);
        $burst_key = 'twss_burst_' . md5($key);

        delete_transient($cache_key);
        delete_transient($burst_key);
    }

    /**
     * Check if OpenAI API request is allowed
     *
     * @since    1.0.2
     * @return   boolean   True if request is allowed
     */
    public function is_openai_request_allowed()
    {
        return $this->is_allowed('openai_api', 20, 60); // 20 requests per minute
    }

    /**
     * Check if Gemini API request is allowed
     *
     * @since    1.0.2
     * @return   boolean   True if request is allowed
     */
    public function is_gemini_request_allowed()
    {
        return $this->is_allowed('gemini_api', 15, 60); // 15 requests per minute (more conservative)
    }

    /**
     * Rate limit prefix for transients
     *
     * @since    1.0.2
     * @access   private
     * @var      string    $prefix
     */
    private $prefix = 'twss_rate_limit_';

    /**
     * Check if action is rate limited
     *
     * @since    1.0.2
     * @param    string    $key        Rate limit key
     * @param    int       $limit      Number of attempts allowed
     * @param    int       $window     Time window in seconds
     * @return   boolean   True if rate limited, false otherwise
     */
    public function is_limited($key, $limit = 10, $window = 3600)
    {
        $transient_key = $this->prefix . md5($key);
        $attempts = get_transient($transient_key);

        if ($attempts === false) {
            // First attempt
            set_transient($transient_key, 1, $window);
            return false;
        }

        if ($attempts >= $limit) {
            return true;
        }

        // Increment attempts
        set_transient($transient_key, $attempts + 1, $window);
        return false;
    }

    /**
     * Reset rate limit for a key
     *
     * @since    1.0.2
     * @param    string    $key    Rate limit key
     */
    public function reset($key)
    {
        $transient_key = $this->prefix . md5($key);
        delete_transient($transient_key);
    }
}
