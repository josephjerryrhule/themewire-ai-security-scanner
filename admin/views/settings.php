<?php

/**
 * Admin Settings View.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

// Save settings if form is submitted
if (isset($_POST['twss_settings_submit'])) {
    check_admin_referer('twss_settings_nonce');

    update_option('twss_ai_provider', sanitize_text_field($_POST['twss_ai_provider']));
    update_option('twss_openai_api_key', sanitize_text_field($_POST['twss_openai_api_key']));
    update_option('twss_gemini_api_key', sanitize_text_field($_POST['twss_gemini_api_key']));
    update_option('twss_scheduled_time', sanitize_text_field($_POST['twss_scheduled_time']));
    update_option('twss_auto_fix', isset($_POST['twss_auto_fix']) ? true : false);
    update_option('twss_send_email', isset($_POST['twss_send_email']) ? true : false);
    update_option('twss_auto_update', isset($_POST['twss_auto_update']) ? true : false);
    update_option('twss_remove_data_on_uninstall', isset($_POST['twss_remove_data_on_uninstall']) ? true : false);

    // Update scheduled scan time
    $scheduler = new Themewire_Security_Scheduler();
    $scheduler->update_scheduled_time($_POST['twss_scheduled_time']);

    echo '<div class="notice notice-success"><p>' . __('Settings saved successfully.', 'themewire-security') . '</p></div>';
}

// Get current settings
$ai_provider = get_option('twss_ai_provider', 'openai');
$openai_api_key = get_option('twss_openai_api_key', '');
$gemini_api_key = get_option('twss_gemini_api_key', '');
$scheduled_time = get_option('twss_scheduled_time', '02:00');
$auto_fix = get_option('twss_auto_fix', false);
$send_email = get_option('twss_send_email', true);
$auto_update = get_option('twss_auto_update', false);
$remove_data = get_option('twss_remove_data_on_uninstall', false);
?>

<div class="wrap themewire-security-wrap">
    <h1><?php _e('Security Settings', 'themewire-security'); ?></h1>

    <form method="post" class="settings-form">
        <?php wp_nonce_field('twss_settings_nonce'); ?>

        <div class="card">
            <h2 class="card-title"><?php _e('AI Configuration', 'themewire-security'); ?></h2>

            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="twss_ai_provider"><?php _e('AI Provider', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <select name="twss_ai_provider" id="twss_ai_provider">
                            <option value="openai" <?php selected($ai_provider, 'openai'); ?>><?php _e('OpenAI', 'themewire-security'); ?></option>
                            <option value="gemini" <?php selected($ai_provider, 'gemini'); ?>><?php _e('Google Gemini', 'themewire-security'); ?></option>
                            <option value="none" <?php selected($ai_provider, 'none'); ?>><?php _e('None (Use built-in analysis)', 'themewire-security'); ?></option>
                        </select>
                        <p class="description"><?php _e('Select which AI provider to use for analyzing suspicious files.', 'themewire-security'); ?></p>
                    </td>
                </tr>

                <tr class="openai-settings" <?php echo $ai_provider !== 'openai' ? 'style="display:none;"' : ''; ?>>
                    <th scope="row">
                        <label for="twss_openai_api_key"><?php _e('OpenAI API Key', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <input type="text" name="twss_openai_api_key" id="twss_openai_api_key" value="<?php echo esc_attr($openai_api_key); ?>" class="regular-text" />
                        <button type="button" id="test-openai-api" class="button"><?php _e('Test Connection', 'themewire-security'); ?></button>
                        <span id="openai-api-status"></span>
                        <p class="description"><?php _e('Enter your OpenAI API key. Get one at', 'themewire-security'); ?> <a href="https://platform.openai.com/api-keys" target="_blank">https://platform.openai.com/api-keys</a></p>
                    </td>
                </tr>

                <tr class="gemini-settings" <?php echo $ai_provider !== 'gemini' ? 'style="display:none;"' : ''; ?>>
                    <th scope="row">
                        <label for="twss_gemini_api_key"><?php _e('Gemini API Key', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <input type="text" name="twss_gemini_api_key" id="twss_gemini_api_key" value="<?php echo esc_attr($gemini_api_key); ?>" class="regular-text" />
                        <button type="button" id="test-gemini-api" class="button"><?php _e('Test Connection', 'themewire-security'); ?></button>
                        <span id="gemini-api-status"></span>
                        <p class="description"><?php _e('Enter your Google Gemini API key. Get one at', 'themewire-security'); ?> <a href="https://ai.google.dev/tutorials/setup" target="_blank">https://ai.google.dev/tutorials/setup</a></p>
                    </td>
                </tr>
            </table>
        </div>

        <div class="card">
            <h2 class="card-title"><?php _e('Scan Schedule', 'themewire-security'); ?></h2>

            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="twss_scheduled_time"><?php _e('Daily Scan Time', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <input type="time" name="twss_scheduled_time" id="twss_scheduled_time" value="<?php echo esc_attr($scheduled_time); ?>" />
                        <p class="description"><?php _e('Set the time for automatic daily scans (24-hour format).', 'themewire-security'); ?></p>
                    </td>
                </tr>

                <tr>
                    <th scope="row"><?php _e('Auto-Fix Issues', 'themewire-security'); ?></th>
                    <td>
                        <label for="twss_auto_fix">
                            <input type="checkbox" name="twss_auto_fix" id="twss_auto_fix" <?php checked($auto_fix); ?> />
                            <?php _e('Automatically fix or quarantine detected issues after scanning', 'themewire-security'); ?>
                        </label>
                    </td>
                </tr>

                <tr>
                    <th scope="row"><?php _e('Email Notifications', 'themewire-security'); ?></th>
                    <td>
                        <label for="twss_send_email">
                            <input type="checkbox" name="twss_send_email" id="twss_send_email" <?php checked($send_email); ?> />
                            <?php _e('Send email notifications after each scan completes', 'themewire-security'); ?>
                        </label>
                    </td>
                </tr>
            </table>
        </div>

        <div class="card">
            <h2 class="card-title"><?php _e('Updates', 'themewire-security'); ?></h2>

            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Auto Update', 'themewire-security'); ?></th>
                    <td>
                        <label for="twss_auto_update">
                            <input type="checkbox" name="twss_auto_update" id="twss_auto_update" <?php checked($auto_update); ?> />
                            <?php _e('Automatically update the plugin when new versions are available', 'themewire-security'); ?>
                        </label>
                        <p class="description"><?php _e('Updates are pulled from the GitHub repository.', 'themewire-security'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Current Version', 'themewire-security'); ?></th>
                    <td>
                        <strong><?php echo TWSS_VERSION; ?></strong>
                        <p class="description">
                            <a href="<?php echo admin_url('admin.php?page=themewire-security-version'); ?>">
                                <?php _e('Check for updates', 'themewire-security'); ?>
                            </a>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <div class="card">
            <h2 class="card-title"><?php _e('Plugin Data', 'themewire-security'); ?></h2>

            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Cleanup on Uninstall', 'themewire-security'); ?></th>
                    <td>
                        <label for="twss_remove_data_on_uninstall">
                            <input type="checkbox" name="twss_remove_data_on_uninstall" id="twss_remove_data_on_uninstall" <?php checked($remove_data); ?> />
                            <?php _e('Remove all plugin data when uninstalling the plugin', 'themewire-security'); ?>
                        </label>
                        <p class="description"><?php _e('If checked, all scan history, settings, and quarantined files will be deleted when the plugin is uninstalled.', 'themewire-security'); ?></p>
                    </td>
                </tr>
            </table>
        </div>

        <input type="submit" name="twss_settings_submit" class="button button-primary" value="<?php _e('Save Settings', 'themewire-security'); ?>" />
    </form>

    <script>
        jQuery(document).ready(function($) {
            // Show/hide API key fields based on selected provider
            $('#twss_ai_provider').on('change', function() {
                var provider = $(this).val();

                if (provider === 'openai') {
                    $('.openai-settings').show();
                    $('.gemini-settings').hide();
                } else if (provider === 'gemini') {
                    $('.openai-settings').hide();
                    $('.gemini-settings').show();
                } else {
                    $('.openai-settings, .gemini-settings').hide();
                }
            });
        });
    </script>
</div>