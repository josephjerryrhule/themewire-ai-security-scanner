<?php

/**
 * GitHub Plugin Updater Class
 * 
 * Handles automatic updates from GitHub releases while maintaining folder structure
 * 
 * @package ThemewireAISecurity
 * @since 1.0.0
 */

class Themewire_Security_GitHub_Updater
{

    private $plugin_file;
    private $plugin_slug;
    private $version;
    private $github_repo;
    private $github_token;

    public function __construct($plugin_file, $github_repo, $version, $github_token = null)
    {
        $this->plugin_file = $plugin_file;
        $this->plugin_slug = dirname(plugin_basename($plugin_file));
        $this->version = $version;
        $this->github_repo = $github_repo;
        $this->github_token = $github_token;

        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_for_update'));
        add_filter('plugins_api', array($this, 'plugin_popup'), 10, 3);
        add_filter('upgrader_pre_install', array($this, 'pre_install'), 10, 2);
        add_filter('upgrader_post_install', array($this, 'post_install'), 10, 3);
        add_filter('upgrader_source_selection', array($this, 'source_selection'), 10, 4);
    }

    /**
     * Check for plugin updates
     */
    public function check_for_update($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        $remote_version = $this->get_remote_version();

        if (version_compare($this->version, $remote_version, '<')) {
            $plugin_data = get_plugin_data($this->plugin_file);

            $transient->response[plugin_basename($this->plugin_file)] = (object) array(
                'slug' => $this->plugin_slug,
                'new_version' => $remote_version,
                'url' => $plugin_data['PluginURI'],
                'package' => $this->get_download_url()
            );
        }

        return $transient;
    }

    /**
     * Get remote version from GitHub releases
     */
    private function get_remote_version()
    {
        $request = wp_remote_get($this->get_api_url());

        if (!is_wp_error($request) && wp_remote_retrieve_response_code($request) === 200) {
            $releases = json_decode(wp_remote_retrieve_body($request), true);

            if (!empty($releases) && is_array($releases)) {
                // Get the latest release (first in array)
                $latest_release = $releases[0];
                return ltrim($latest_release['tag_name'], 'v');
            }
        }

        return false;
    }

    /**
     * Get GitHub API URL
     */
    private function get_api_url()
    {
        return sprintf('https://api.github.com/repos/%s/releases', $this->github_repo);
    }

    /**
     * Get download URL for latest release
     */
    private function get_download_url()
    {
        $request = wp_remote_get($this->get_api_url());

        if (!is_wp_error($request) && wp_remote_retrieve_response_code($request) === 200) {
            $releases = json_decode(wp_remote_retrieve_body($request), true);

            if (!empty($releases) && is_array($releases)) {
                $latest_release = $releases[0];

                // Look for the main zip asset
                if (!empty($latest_release['assets'])) {
                    foreach ($latest_release['assets'] as $asset) {
                        if (strpos($asset['name'], '.zip') !== false) {
                            return $asset['browser_download_url'];
                        }
                    }
                }

                // Fallback to zipball if no assets
                return $latest_release['zipball_url'];
            }
        }

        return false;
    }

    /**
     * Show plugin information popup
     */
    public function plugin_popup($result, $action, $args)
    {
        if ($action !== 'plugin_information' || $args->slug !== $this->plugin_slug) {
            return $result;
        }

        $plugin_data = get_plugin_data($this->plugin_file);
        $remote_version = $this->get_remote_version();

        return (object) array(
            'name' => $plugin_data['Name'],
            'slug' => $this->plugin_slug,
            'version' => $remote_version,
            'author' => $plugin_data['Author'],
            'homepage' => $plugin_data['PluginURI'],
            'short_description' => $plugin_data['Description'],
            'sections' => array(
                'Description' => $plugin_data['Description'],
                'Installation' => 'Upload and activate the plugin.',
                'Changelog' => $this->get_changelog()
            ),
            'download_link' => $this->get_download_url()
        );
    }

    /**
     * Get changelog from GitHub releases
     */
    private function get_changelog()
    {
        $request = wp_remote_get($this->get_api_url());

        if (!is_wp_error($request) && wp_remote_retrieve_response_code($request) === 200) {
            $releases = json_decode(wp_remote_retrieve_body($request), true);

            $changelog = '<h4>Recent Releases</h4>';

            if (!empty($releases) && is_array($releases)) {
                foreach (array_slice($releases, 0, 5) as $release) {
                    $changelog .= '<h4>' . esc_html($release['tag_name']) . '</h4>';
                    $changelog .= '<p>' . wp_kses_post($release['body']) . '</p>';
                }
            }

            return $changelog;
        }

        return 'No changelog available.';
    }

    /**
     * Pre-install hook to backup current plugin
     */
    public function pre_install($result, $hook_extra)
    {
        if (isset($hook_extra['plugin']) && $hook_extra['plugin'] === plugin_basename($this->plugin_file)) {
            // Create backup before installation
            $this->backup_current_installation();
        }

        return $result;
    }

    /**
     * Post-install hook to maintain folder structure
     */
    public function post_install($result, $hook_extra, $child_result)
    {
        if (isset($hook_extra['plugin']) && $hook_extra['plugin'] === plugin_basename($this->plugin_file)) {
            // Ensure the plugin maintains its folder structure
            $this->maintain_folder_structure($child_result);
        }

        return $result;
    }

    /**
     * Source selection to handle GitHub zip structure
     */
    public function source_selection($source, $remote_source, $upgrader, $hook_extra = null)
    {
        if (isset($hook_extra['plugin']) && $hook_extra['plugin'] === plugin_basename($this->plugin_file)) {
            // GitHub zips often have an extra folder level
            $corrected_source = $this->correct_source_path($source, $remote_source);
            if ($corrected_source !== $source) {
                return $corrected_source;
            }
        }

        return $source;
    }

    /**
     * Correct the source path for GitHub downloads
     */
    private function correct_source_path($source, $remote_source)
    {
        global $wp_filesystem;

        // List contents of the source directory
        $dirlist = $wp_filesystem->dirlist($remote_source);

        if (!empty($dirlist)) {
            // GitHub typically creates a single directory with repo name and commit hash
            $first_dir = array_keys($dirlist)[0];

            // Check if there's only one directory and it contains our plugin
            if (count($dirlist) === 1 && $wp_filesystem->is_dir($remote_source . $first_dir)) {
                $potential_source = trailingslashit($remote_source) . trailingslashit($first_dir);

                // Verify this contains our plugin file
                $plugin_files = $wp_filesystem->dirlist($potential_source);
                if (!empty($plugin_files)) {
                    foreach ($plugin_files as $file => $file_data) {
                        if (strpos($file, '.php') !== false && $file_data['type'] === 'f') {
                            // Check if this looks like our main plugin file
                            $file_content = $wp_filesystem->get_contents($potential_source . $file);
                            if (strpos($file_content, 'Plugin Name:') !== false) {
                                return $potential_source;
                            }
                        }
                    }
                }
            }
        }

        return $source;
    }

    /**
     * Create backup of current installation
     */
    private function backup_current_installation()
    {
        $plugin_dir = dirname($this->plugin_file);
        $backup_dir = $plugin_dir . '-backup-' . date('Y-m-d-H-i-s');

        if (function_exists('wp_filesystem') && WP_Filesystem()) {
            global $wp_filesystem;
            $wp_filesystem->copy($plugin_dir, $backup_dir, true);
        }
    }

    /**
     * Maintain proper folder structure after installation
     */
    private function maintain_folder_structure($child_result)
    {
        if (!isset($child_result['destination'])) {
            return;
        }

        $destination = $child_result['destination'];
        $expected_path = WP_PLUGIN_DIR . '/' . $this->plugin_slug;

        // If the destination doesn't match expected path, correct it
        if ($destination !== $expected_path && function_exists('wp_filesystem') && WP_Filesystem()) {
            global $wp_filesystem;

            if ($wp_filesystem->exists($destination) && !$wp_filesystem->exists($expected_path)) {
                $wp_filesystem->move($destination, $expected_path);
            }
        }
    }

    /**
     * Get headers for GitHub API requests
     */
    private function get_request_headers()
    {
        $headers = array(
            'User-Agent' => 'WordPress Plugin Updater'
        );

        if ($this->github_token) {
            $headers['Authorization'] = 'token ' . $this->github_token;
        }

        return $headers;
    }

    /**
     * Clear update transients (for manual refresh)
     */
    public function clear_cache()
    {
        delete_site_transient('update_plugins');
    }
}
