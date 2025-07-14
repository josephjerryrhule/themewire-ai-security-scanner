<?php
/**
 * GitHub updater functionality for the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_GitHub_Updater {

    /**
     * GitHub username
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $github_username
     */
    private $github_username;

    /**
     * GitHub repository name
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $github_repo
     */
    private $github_repo;

    /**
     * Plugin slug
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $plugin_slug
     */
    private $plugin_slug;

    /**
     * Plugin data
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $plugin_data
     */
    private $plugin_data;

    /**
     * Initialize the updater
     *
     * @since    1.0.0
     * @param    string    $github_username    GitHub username
     * @param    string    $github_repo        GitHub repository name
     * @param    string    $plugin_file        Main plugin file
     */
    public function __construct($github_username, $github_repo, $plugin_file) {
        $this->github_username = $github_username;
        $this->github_repo = $github_repo;
        $this->plugin_slug = plugin_basename($plugin_file);
        
        // Get plugin data
        if (!function_exists('get_plugin_data')) {
            require_once(ABSPATH . 'wp-admin/includes/plugin.php');
        }
        $this->plugin_data = get_plugin_data($plugin_file);
        
        // Define hooks
        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_update'));
        add_filter('plugins_api', array($this, 'plugin_info'), 10, 3);
        add_filter('upgrader_post_install', array($this, 'post_install'), 10, 3);
    }

    /**
     * Check for updates
     *
     * @since    1.0.0
     * @param    object    $transient    Update transient
     * @return   object    Modified update transient
     */
    public function check_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        // Get release info from GitHub
        $release_info = $this->get_github_release_info();
        
        if ($this->is_update_available($release_info)) {
            // Format the response for WP updater
            $response = new stdClass();
            $response->slug = $this->plugin_slug;
            $response->plugin = $this->plugin_slug;
            $response->new_version = ltrim($release_info['tag_name'], 'v');
            $response->url = $this->plugin_data['PluginURI'];
            $response->package = $release_info['zipball_url'];
            $response->icons = array(
                '1x' => isset($this->plugin_data['IconURL']) ? $this->plugin_data['IconURL'] : '',
                '2x' => isset($this->plugin_data['IconURL']) ? $this->plugin_data['IconURL'] : ''
            );
            
            $transient->response[$this->plugin_slug] = $response;
        }
        
        return $transient;
    }

    /**
     * Get GitHub release info
     *
     * @since    1.0.0
     * @return   array|false    Release info or false on failure
     */
    private function get_github_release_info() {
        // Cache key for release info
        $cache_key = 'twss_github_release_info';
        
        // Try to get from cache first
        $release_info = get_transient($cache_key);
        
        if (false === $release_info) {
            // Get latest release info from GitHub API
            $url = "https://api.github.com/repos/{$this->github_username}/{$this->github_repo}/releases/latest";
            $response = wp_remote_get($url, array(
                'headers' => array(
                    'Accept' => 'application/vnd.github.v3+json',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version')
                )
            ));
            
            if (!is_wp_error($response) && 200 === wp_remote_retrieve_response_code($response)) {
                $release_info = json_decode(wp_remote_retrieve_body($response), true);
                
                // Cache for 6 hours
                set_transient($cache_key, $release_info, 6 * HOUR_IN_SECONDS);
            } else {
                return false;
            }
        }
        
        return $release_info;
    }

    /**
     * Check if update is available
     *
     * @since    1.0.0
     * @param    array     $release_info    GitHub release info
     * @return   boolean   True if update available, false otherwise
     */
    private function is_update_available($release_info) {
        if (!$release_info) {
            return false;
        }
        
        // Get current version
        $current_version = $this->plugin_data['Version'];
        
        // Get latest version
        $latest_version = ltrim($release_info['tag_name'], 'v');
        
        // Compare versions
        return version_compare($latest_version, $current_version, '>');
    }

    /**
     * Provide plugin info to WP updates API
     *
     * @since    1.0.0
     * @param    false|object|array    $result    Result object or array
     * @param    string                $action    API action
     * @param    object                $args      API arguments
     * @return   object|false          Plugin info or false
     */
    public function plugin_info($result, $action, $args) {
        // Check if this is our plugin
        if ('plugin_information' !== $action || !isset($args->slug) || $args->slug !== dirname($this->plugin_slug)) {
            return $result;
        }
        
        // Get release info
        $release_info = $this->get_github_release_info();
        
        if (!$release_info) {
            return $result;
        }
        
        // Build plugin info
        $plugin = new stdClass();
        $plugin->name = $this->plugin_data['Name'];
        $plugin->slug = dirname($this->plugin_slug);
        $plugin->version = ltrim($release_info['tag_name'], 'v');
        $plugin->author = $this->plugin_data['Author'];
        $plugin->author_profile = $this->plugin_data['AuthorURI'];
        $plugin->last_updated = date('Y-m-d', strtotime($release_info['published_at']));
        $plugin->homepage = $this->plugin_data['PluginURI'];
        $plugin->short_description = $this->plugin_data['Description'];
        
        // Set download link
        $plugin->download_link = $release_info['zipball_url'];
        
        // Set sections
        $plugin->sections = array(
            'description' => $this->plugin_data['Description'],
            'changelog' => $this->format_github_changelog($release_info['body'])
        );
        
        // Set banners
        $plugin->banners = array(
            'low' => isset($this->plugin_data['BannerLowURL']) ? $this->plugin_data['BannerLowURL'] : '',
            'high' => isset($this->plugin_data['BannerHighURL']) ? $this->plugin_data['BannerHighURL'] : ''
        );
        
        return $plugin;
    }

    /**
     * Format GitHub changelog
     *
     * @since    1.0.0
     * @param    string    $changelog    GitHub release body
     * @return   string    Formatted changelog
     */
    private function format_github_changelog($changelog) {
        // Convert markdown to HTML
        if (!empty($changelog)) {
            // Simple markdown formatting
            $changelog = preg_replace('/\*\*(.*?)\*\*/i', '<strong>$1</strong>', $changelog);
            $changelog = preg_replace('/\*(.*?)\*/i', '<em>$1</em>', $changelog);
            $changelog = preg_replace('/\- (.*?)(\n|$)/i', '<li>$1</li>', $changelog);
            $changelog = preg_replace('/\n\n/i', '</ul><ul>', $changelog);
            
            // Wrap in ul tags
            $changelog = '<ul>' . $changelog . '</ul>';
            
            // Replace multiple ul tags with single ones
            $changelog = str_replace('</ul><ul>', '<br>', $changelog);
        } else {
            $changelog = 'No changelog provided for this release.';
        }
        
        return $changelog;
    }

    /**
     * Actions after the plugin update is complete
     *
     * @since    1.0.0
     * @param    bool      $response   Installation response
     * @param    array     $hook_extra Extra arguments passed to hooked filters
     * @param    array     $result     Installation result data
     * @return   array     Modified installation result data
     */
    public function post_install($response, $hook_extra, $result) {
        global $wp_filesystem;
        
        // Check if this is our plugin
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== $this->plugin_slug) {
            return $result;
        }
        
        // Ensure WordPress filesystem is initialized
        if (!$wp_filesystem) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
            WP_Filesystem();
        }
        
        // GitHub stores the plugin in a subfolder, need to move files up one level
        $plugin_folder = $wp_filesystem->wp_plugins_dir() . dirname($this->plugin_slug);
        $github_folder = trailingslashit($result['destination']);
        
        // Get the actual plugin folder name (it might have the version number appended)
        $folders = scandir($github_folder);
        $github_plugin_folder = '';
        
        foreach ($folders as $folder) {
            if ('.' === $folder || '..' === $folder) {
                continue;
            }
            
            if (is_dir($github_folder . $folder)) {
                $github_plugin_folder = $github_folder . $folder;
                break;
            }
        }
        
        if (!empty($github_plugin_folder)) {
            // Move all plugin files from GitHub subfolder to proper plugin folder
            $files = scandir($github_plugin_folder);
            
            foreach ($files as $file) {
                if ('.' === $file || '..' === $file) {
                    continue;
                }
                
                $wp_filesystem->move($github_plugin_folder . '/' . $file, $github_folder . $file, true);
            }
            
            // Remove GitHub subfolder
            $wp_filesystem->rmdir($github_plugin_folder);
        }
        
        return $result;
    }

    /**
     * Force update check
     *
     * @since    1.0.0
     */
    public function force_update_check() {
        delete_transient('twss_github_release_info');
        delete_site_transient('update_plugins');
        wp_update_plugins();
    }
}