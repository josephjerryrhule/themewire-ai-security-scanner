<?php

/**
 * Admin Version View.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

// Force update check if requested
if (isset($_GET['force-check']) && $_GET['force-check'] == '1') {
    try {
        $updater = new Themewire_Security_GitHub_Updater(
            TWSS_PLUGIN_DIR . 'themewire-ai-security-scanner.php',
            TWSS_GITHUB_USERNAME . '/' . TWSS_GITHUB_REPO,
            TWSS_VERSION
        );
        $updater->clear_cache();

        echo '<div class="notice notice-success"><p>' . __('Update check completed.', 'themewire-security') . '</p></div>';
    } catch (Exception $e) {
        echo '<div class="notice notice-error"><p>' . sprintf(__('Error checking for updates: %s', 'themewire-security'), $e->getMessage()) . '</p></div>';
    }
}

// Get plugin data
$plugin_data = get_plugin_data(TWSS_PLUGIN_DIR . 'themewire-ai-security-scanner.php');
$current_version = $plugin_data['Version'];

// Get update information
$update_data = get_site_transient('update_plugins');
$has_update = false;
$new_version = '';

if (isset($update_data->response[TWSS_PLUGIN_BASENAME])) {
    $has_update = true;
    $new_version = $update_data->response[TWSS_PLUGIN_BASENAME]->new_version;
}

// Get build information
// Get build date from plugin file creation time
$plugin_file = TWSS_PLUGIN_DIR . 'themewire-ai-security-scanner.php';
$build_date = date('Y-m-d', filectime($plugin_file));

// Get last modified date from plugin file modification time
$last_modified = date('Y-m-d H:i:s', filemtime($plugin_file));

// Try to get last modified by from git, fallback to unknown
$modified_by = 'unknown';
$git_cmd = 'cd ' . escapeshellarg(dirname($plugin_file)) . ' && git log -1 --pretty=format:"%an" -- ' . escapeshellarg(basename($plugin_file));
$git_output = @shell_exec($git_cmd);
if ($git_output) {
    $modified_by = trim($git_output);
}

// Get repository information
$repo_url = "https://github.com/" . TWSS_GITHUB_USERNAME . "/" . TWSS_GITHUB_REPO;
?>

<div class="wrap themewire-security-wrap">
    <h1><?php _e('Version Information', 'themewire-security'); ?></h1>

    <div class="card">
        <h2 class="card-title"><?php _e('Current Version', 'themewire-security'); ?></h2>

        <table class="form-table">
            <tr>
                <th scope="row"><?php _e('Version', 'themewire-security'); ?></th>
                <td>
                    <strong><?php echo esc_html($current_version); ?></strong>
                    <?php if ($has_update): ?>
                        <span class="update-available">
                            <?php printf(__('(Update to %s available)', 'themewire-security'), $new_version); ?>
                        </span>
                    <?php endif; ?>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php _e('Build Date', 'themewire-security'); ?></th>
                <td><?php echo esc_html($build_date); ?></td>
            </tr>

            <tr>
                <th scope="row"><?php _e('Last Modified', 'themewire-security'); ?></th>
                <td><?php echo esc_html($last_modified); ?></td>
            </tr>

            <tr>
                <th scope="row"><?php _e('Modified By', 'themewire-security'); ?></th>
                <td><?php echo esc_html($modified_by); ?></td>
            </tr>
        </table>

        <?php if ($has_update): ?>
            <div class="notice notice-warning">
                <p>
                    <?php printf(__('A new version (%s) is available. Please update now.', 'themewire-security'), $new_version); ?>
                    <a href="<?php echo wp_nonce_url(admin_url('update.php?action=upgrade-plugin&plugin=' . TWSS_PLUGIN_BASENAME), 'upgrade-plugin_' . TWSS_PLUGIN_BASENAME); ?>" class="button button-primary">
                        <?php _e('Update Now', 'themewire-security'); ?>
                    </a>
                </p>
            </div>
        <?php else: ?>
            <div class="notice notice-success">
                <p><?php _e('You are running the latest version of Themewire AI Security Scanner.', 'themewire-security'); ?></p>
            </div>
        <?php endif; ?>

        <p>
            <a href="<?php echo admin_url('admin.php?page=themewire-security-version&force-check=1'); ?>" class="button">
                <?php _e('Check for Updates', 'themewire-security'); ?>
            </a>
        </p>
    </div>

    <div class="card">
        <h2 class="card-title"><?php _e('GitHub Repository', 'themewire-security'); ?></h2>
        <p><?php _e('This plugin is maintained on GitHub. You can contribute, report issues, or view the source code at the repository below:', 'themewire-security'); ?></p>
        <p>
            <a href="<?php echo esc_url($repo_url); ?>" target="_blank" class="button">
                <?php _e('View on GitHub', 'themewire-security'); ?>
            </a>
            <a href="<?php echo esc_url($repo_url . '/issues'); ?>" target="_blank" class="button">
                <?php _e('Report an Issue', 'themewire-security'); ?>
            </a>
        </p>
    </div>
</div>