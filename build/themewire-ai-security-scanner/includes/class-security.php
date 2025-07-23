<?php

/**
 * Additional security measures for the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.2
 * @package    Themewire_Security
 */

class Themewire_Security_Hardening
{

    public function __construct()
    {
        add_action('init', array($this, 'add_security_headers'));
        add_action('wp_ajax_nopriv_twss_', array($this, 'block_unauthorized_ajax'));
    }

    public function add_security_headers()
    {
        if (is_admin() && strpos($_SERVER['REQUEST_URI'], 'themewire-security') !== false) {
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');
            header('X-XSS-Protection: 1; mode=block');
        }
    }

    public function block_unauthorized_ajax()
    {
        wp_die('Unauthorized access', 'Unauthorized', array('response' => 403));
    }

    public static function verify_nonce($action = 'twss_nonce')
    {
        if (!wp_verify_nonce($_POST['nonce'] ?? '', $action)) {
            wp_die('Security check failed', 'Security Error', array('response' => 403));
        }
    }
}
