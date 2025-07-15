<?php

/**
 * Smart file validation and comparison functionality.
 *
 * @link       https://themewire.com
 * @since      1.0.2
 *
 * @package    Themewire_Security
 */

class Themewire_Security_File_Validator
{
    /**
     * Logger instance
     */
    private $logger;

    /**
     * AI Analyzer instance
     */
    private $ai_analyzer;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->logger = new Themewire_Security_Logger();
        $this->ai_analyzer = new Themewire_Security_AI_Analyzer();
    }

    /**
     * Validate a plugin file using smart comparison
     *
     * @param string $file_path     Full path to the file
     * @param string $plugin_slug   Plugin slug
     * @return array Validation result
     */
    public function validate_plugin_file($file_path, $plugin_slug)
    {
        $this->logger->info('Validating plugin file', array(
            'file_path' => $file_path,
            'plugin_slug' => $plugin_slug
        ));

        // Step 1: Check if plugin exists on WordPress.org
        $wp_org_data = $this->get_wordpress_org_plugin_data($plugin_slug);

        if ($wp_org_data) {
            $this->logger->info('Plugin found on WordPress.org, comparing against official version');
            return $this->compare_with_wordpress_org($file_path, $plugin_slug, $wp_org_data);
        }

        // Step 2: Check for GitHub repository
        $github_repo = $this->find_github_repository($plugin_slug, $file_path);

        if ($github_repo) {
            $this->logger->info('GitHub repository found, comparing against repository');
            return $this->compare_with_github($file_path, $github_repo);
        }

        // Step 3: Use AI analysis as fallback
        $this->logger->info('No official source found, using AI analysis');
        return $this->analyze_with_ai($file_path);
    }

    /**
     * Validate a theme file using smart comparison
     *
     * @param string $file_path   Full path to the file
     * @param string $theme_slug  Theme slug
     * @return array Validation result
     */
    public function validate_theme_file($file_path, $theme_slug)
    {
        $this->logger->info('Validating theme file', array(
            'file_path' => $file_path,
            'theme_slug' => $theme_slug
        ));

        // Check WordPress.org first
        $wp_org_data = $this->get_wordpress_org_theme_data($theme_slug);

        if ($wp_org_data) {
            return $this->compare_theme_with_wordpress_org($file_path, $theme_slug, $wp_org_data);
        }

        // Check for GitHub repository
        $github_repo = $this->find_github_repository($theme_slug, $file_path);

        if ($github_repo) {
            return $this->compare_with_github($file_path, $github_repo);
        }

        // Use AI analysis
        return $this->analyze_with_ai($file_path);
    }

    /**
     * Get plugin data from WordPress.org API
     *
     * @param string $plugin_slug Plugin slug
     * @return array|false Plugin data or false
     */
    private function get_wordpress_org_plugin_data($plugin_slug)
    {
        $cache_key = 'twss_wp_org_plugin_' . $plugin_slug;
        $cached_data = get_transient($cache_key);

        if ($cached_data !== false) {
            return $cached_data;
        }

        $api_url = "https://api.wordpress.org/plugins/info/1.0/{$plugin_slug}.json";

        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
            'user-agent' => 'Themewire Security Scanner'
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            $this->logger->warning('Failed to fetch plugin data from WordPress.org', array(
                'plugin_slug' => $plugin_slug,
                'error' => is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response)
            ));
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);

        if (!$data || isset($data['error'])) {
            return false;
        }

        // Cache for 24 hours
        set_transient($cache_key, $data, 24 * HOUR_IN_SECONDS);

        return $data;
    }

    /**
     * Get theme data from WordPress.org API
     *
     * @param string $theme_slug Theme slug
     * @return array|false Theme data or false
     */
    private function get_wordpress_org_theme_data($theme_slug)
    {
        $cache_key = 'twss_wp_org_theme_' . $theme_slug;
        $cached_data = get_transient($cache_key);

        if ($cached_data !== false) {
            return $cached_data;
        }

        $api_url = "https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={$theme_slug}";

        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
            'user-agent' => 'Themewire Security Scanner'
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);

        if (!$data || isset($data['error'])) {
            return false;
        }

        // Cache for 24 hours
        set_transient($cache_key, $data, 24 * HOUR_IN_SECONDS);

        return $data;
    }

    /**
     * Compare file with WordPress.org official version
     *
     * @param string $file_path     File path
     * @param string $plugin_slug   Plugin slug
     * @param array  $wp_org_data   WordPress.org data
     * @return array Validation result
     */
    private function compare_with_wordpress_org($file_path, $plugin_slug, $wp_org_data)
    {
        $result = array(
            'status' => 'clean',
            'confidence' => 0,
            'method' => 'wordpress_org_comparison',
            'indicators' => array(),
            'suggested_action' => 'none'
        );

        // Get the relative path within the plugin
        $plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;
        $relative_path = str_replace($plugin_dir . '/', '', $file_path);

        // Download the official file for comparison
        $official_content = $this->download_official_plugin_file($plugin_slug, $wp_org_data['version'], $relative_path);

        if ($official_content === false) {
            // File doesn't exist in official version - suspicious
            $result['status'] = 'suspicious';
            $result['confidence'] = 85;
            $result['indicators'][] = 'File not found in official plugin version';
            $result['suggested_action'] = 'quarantine';
            return $result;
        }

        $current_content = file_get_contents($file_path);

        if ($current_content === $official_content) {
            // Files match - clean
            $result['status'] = 'clean';
            $result['confidence'] = 95;
            $result['indicators'][] = 'File matches official WordPress.org version';
            return $result;
        }

        // Files don't match - analyze the differences
        $diff_analysis = $this->analyze_file_differences($official_content, $current_content);

        if ($diff_analysis['is_malicious']) {
            $result['status'] = 'infected';
            $result['confidence'] = $diff_analysis['confidence'];
            $result['indicators'] = $diff_analysis['indicators'];
            $result['suggested_action'] = 'restore_from_official';
        } else {
            $result['status'] = 'modified';
            $result['confidence'] = 60;
            $result['indicators'][] = 'File has been modified from official version';
            $result['suggested_action'] = 'review';
        }

        return $result;
    }

    /**
     * Find GitHub repository for a plugin/theme
     *
     * @param string $slug      Plugin/theme slug
     * @param string $file_path File path to check headers
     * @return array|false Repository info or false
     */
    private function find_github_repository($slug, $file_path)
    {
        // First, check plugin/theme headers for GitHub URL
        $main_file = $this->find_main_plugin_file($file_path);

        if ($main_file) {
            $headers = get_file_data($main_file, array(
                'GitHub URI' => 'GitHub URI',
                'GitHub Plugin URI' => 'GitHub Plugin URI',
                'Plugin URI' => 'Plugin URI',
                'Theme URI' => 'Theme URI'
            ));

            foreach ($headers as $header) {
                if (preg_match('/github\.com\/([^\/]+)\/([^\/]+)/i', $header, $matches)) {
                    return array(
                        'owner' => $matches[1],
                        'repo' => $matches[2],
                        'url' => $header
                    );
                }
            }
        }

        // Try common GitHub repository patterns
        $common_patterns = array(
            "https://api.github.com/repos/{$slug}/{$slug}",
            "https://api.github.com/repos/wp-{$slug}/{$slug}",
            "https://api.github.com/repos/{$slug}/wp-{$slug}"
        );

        foreach ($common_patterns as $pattern) {
            if ($this->check_github_repository_exists($pattern)) {
                preg_match('/github\.com\/repos\/([^\/]+)\/([^\/]+)/', $pattern, $matches);
                return array(
                    'owner' => $matches[1],
                    'repo' => $matches[2],
                    'url' => str_replace('api.', '', str_replace('/repos', '', $pattern))
                );
            }
        }

        return false;
    }

    /**
     * Check if GitHub repository exists
     *
     * @param string $api_url GitHub API URL
     * @return boolean
     */
    private function check_github_repository_exists($api_url)
    {
        $response = wp_remote_get($api_url, array(
            'timeout' => 10,
            'headers' => array(
                'User-Agent' => 'Themewire Security Scanner'
            )
        ));

        return !is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200;
    }

    /**
     * Analyze differences between two file contents
     *
     * @param string $official_content Official file content
     * @param string $current_content  Current file content
     * @return array Analysis result
     */
    private function analyze_file_differences($official_content, $current_content)
    {
        $result = array(
            'is_malicious' => false,
            'confidence' => 0,
            'indicators' => array()
        );

        // Get the differences
        $diff = $this->simple_diff($official_content, $current_content);

        // Analyze added lines for malicious patterns
        $malicious_patterns = array(
            'eval\s*\(' => 'Eval function added',
            'base64_decode\s*\(' => 'Base64 decode added',
            'system\s*\(' => 'System command execution added',
            'exec\s*\(' => 'Command execution added',
            'shell_exec\s*\(' => 'Shell execution added',
            'file_get_contents\s*\(\s*[\'"]https?://' => 'Remote file inclusion added',
            'curl_exec\s*\(' => 'CURL execution added',
            '<iframe[^>]*src\s*=' => 'Suspicious iframe added'
        );

        foreach ($diff['added'] as $line) {
            foreach ($malicious_patterns as $pattern => $description) {
                if (preg_match('/' . $pattern . '/i', $line)) {
                    $result['is_malicious'] = true;
                    $result['confidence'] += 25;
                    $result['indicators'][] = $description . ': ' . trim($line);
                }
            }
        }

        // Check for obfuscated additions
        foreach ($diff['added'] as $line) {
            if (strlen($line) > 200 && preg_match('/[\x00-\x1F\x7F-\xFF]/', $line)) {
                $result['is_malicious'] = true;
                $result['confidence'] += 30;
                $result['indicators'][] = 'Obfuscated code added';
            }
        }

        $result['confidence'] = min(100, $result['confidence']);

        return $result;
    }

    /**
     * Simple diff implementation
     *
     * @param string $old_content Old content
     * @param string $new_content New content
     * @return array Diff result
     */
    private function simple_diff($old_content, $new_content)
    {
        $old_lines = explode("\n", $old_content);
        $new_lines = explode("\n", $new_content);

        $added = array_diff($new_lines, $old_lines);
        $removed = array_diff($old_lines, $new_lines);

        return array(
            'added' => $added,
            'removed' => $removed
        );
    }

    /**
     * Download official plugin file from WordPress.org
     *
     * @param string $plugin_slug Plugin slug
     * @param string $version     Plugin version
     * @param string $file_path   Relative file path
     * @return string|false File content or false
     */
    private function download_official_plugin_file($plugin_slug, $version, $file_path)
    {
        $download_url = "https://downloads.wordpress.org/plugin/{$plugin_slug}.{$version}.zip";

        // For simplicity, we'll use SVN API which is more direct
        $svn_url = "https://plugins.svn.wordpress.org/{$plugin_slug}/tags/{$version}/{$file_path}";

        $response = wp_remote_get($svn_url, array(
            'timeout' => 30,
            'user-agent' => 'Themewire Security Scanner'
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        return wp_remote_retrieve_body($response);
    }

    /**
     * Find main plugin file
     *
     * @param string $file_path Any file in the plugin
     * @return string|false Main plugin file path
     */
    private function find_main_plugin_file($file_path)
    {
        // Get plugin directory
        $plugin_dir = dirname($file_path);

        // Look for main plugin file (PHP file with plugin headers)
        $files = glob($plugin_dir . '/*.php');

        foreach ($files as $file) {
            $content = file_get_contents($file, false, null, 0, 8192); // Read first 8KB
            if (strpos($content, 'Plugin Name:') !== false) {
                return $file;
            }
        }

        return false;
    }

    /**
     * Analyze file with AI when no official source is available
     *
     * @param string $file_path File path
     * @return array Analysis result
     */
    private function analyze_with_ai($file_path)
    {
        $ai_result = $this->ai_analyzer->analyze_file($file_path);

        // Enhanced analysis result with more details
        $status = 'unknown';
        $confidence = 50;

        if ($ai_result['is_malware']) {
            $status = 'suspicious';
            $confidence = 75; // Higher confidence for AI-detected malware
        }

        // Check if file is in an unusual location
        if ($this->is_file_in_unusual_location($file_path)) {
            $status = 'suspicious';
            $confidence = max($confidence, 80);
        }

        return array(
            'status' => $status,
            'confidence' => $confidence,
            'method' => 'ai_analysis',
            'indicators' => array($ai_result['explanation']),
            'suggested_action' => $ai_result['suggested_fix'] ?: 'review',
            'ai_verdict' => array(
                'is_malware' => $ai_result['is_malware'],
                'explanation' => $ai_result['explanation'],
                'suggested_fix' => $ai_result['suggested_fix']
            )
        );
    }

    /**
     * Check if file is in an unusual location for its type
     *
     * @param string $file_path File path
     * @return boolean True if location is unusual
     */
    private function is_file_in_unusual_location($file_path)
    {
        $file_extension = pathinfo($file_path, PATHINFO_EXTENSION);

        // PHP files in uploads directory are very suspicious
        if ($file_extension === 'php' && strpos($file_path, 'wp-content/uploads') !== false) {
            return true;
        }

        // Executable files in unexpected locations
        $suspicious_extensions = array('exe', 'bat', 'cmd', 'sh', 'com', 'scr', 'pif');
        if (in_array(strtolower($file_extension), $suspicious_extensions)) {
            return true;
        }

        // Hidden files (starting with dot) in plugin/theme directories
        $filename = basename($file_path);
        if ($filename[0] === '.' && strlen($filename) > 1) {
            if (
                strpos($file_path, 'wp-content/plugins') !== false ||
                strpos($file_path, 'wp-content/themes') !== false
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate and flag injected files not part of original plugin/theme
     *
     * @param string $file_path File path
     * @param string $plugin_or_theme_slug Slug of plugin or theme
     * @param string $type 'plugin' or 'theme'
     * @return array Validation result
     */
    public function validate_injected_file($file_path, $plugin_or_theme_slug, $type = 'plugin')
    {
        $this->logger->info('Checking for injected file', array(
            'file_path' => $file_path,
            'slug' => $plugin_or_theme_slug,
            'type' => $type
        ));

        $result = array(
            'status' => 'unknown',
            'confidence' => 0,
            'method' => 'injection_detection',
            'indicators' => array(),
            'suggested_action' => 'review'
        );

        // Check if file should exist in official version
        if ($type === 'plugin') {
            $wp_org_data = $this->get_wordpress_org_plugin_data($plugin_or_theme_slug);
        } else {
            $wp_org_data = $this->get_wordpress_org_theme_data($plugin_or_theme_slug);
        }

        if ($wp_org_data) {
            // Get relative path
            $base_dir = $type === 'plugin' ? WP_PLUGIN_DIR : get_theme_root();
            $plugin_dir = $base_dir . '/' . $plugin_or_theme_slug;
            $relative_path = str_replace($plugin_dir . '/', '', $file_path);

            // Try to download the official file
            $official_content = $this->download_official_file($plugin_or_theme_slug, $wp_org_data['version'], $relative_path, $type);

            if ($official_content === false) {
                // File doesn't exist in official version - likely injected
                $result['status'] = 'injected';
                $result['confidence'] = 90;
                $result['indicators'][] = 'File not found in official ' . $type . ' version - likely injected';
                $result['suggested_action'] = 'quarantine';

                // Use AI to analyze the injected file
                $ai_result = $this->ai_analyzer->analyze_file($file_path);
                if ($ai_result['is_malware']) {
                    $result['status'] = 'infected';
                    $result['confidence'] = 95;
                    $result['indicators'][] = 'AI analysis confirms malicious content: ' . $ai_result['explanation'];
                    $result['suggested_action'] = 'delete';
                }
            }
        }

        return $result;
    }

    /**
     * Download official file from WordPress.org or GitHub
     *
     * @param string $slug Plugin/theme slug
     * @param string $version Version
     * @param string $file_path Relative file path
     * @param string $type 'plugin' or 'theme'
     * @return string|false File content or false
     */
    private function download_official_file($slug, $version, $file_path, $type = 'plugin')
    {
        if ($type === 'plugin') {
            return $this->download_official_plugin_file($slug, $version, $file_path);
        } else {
            return $this->download_official_theme_file($slug, $version, $file_path);
        }
    }

    /**
     * Download official theme file from WordPress.org
     *
     * @param string $theme_slug Theme slug
     * @param string $version Theme version
     * @param string $file_path Relative file path
     * @return string|false File content or false
     */
    private function download_official_theme_file($theme_slug, $version, $file_path)
    {
        // Use SVN API for themes
        $svn_url = "https://themes.svn.wordpress.org/{$theme_slug}/{$version}/{$file_path}";

        $response = wp_remote_get($svn_url, array(
            'timeout' => 30,
            'user-agent' => 'Themewire Security Scanner'
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        return wp_remote_retrieve_body($response);
    }
}
