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
    update_option('twss_openrouter_api_key', sanitize_text_field($_POST['twss_openrouter_api_key']));
    update_option('twss_openrouter_model', sanitize_text_field($_POST['twss_openrouter_model']));
    update_option('twss_use_fallback_ai', isset($_POST['twss_use_fallback_ai']) ? true : false);
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
$openrouter_api_key = get_option('twss_openrouter_api_key', '');
$openrouter_model = get_option('twss_openrouter_model', 'deepseek/deepseek-chat-v3-0324:free');
$use_fallback_ai = get_option('twss_use_fallback_ai', true);
$use_fallback_ai = get_option('twss_use_fallback_ai', true);
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
            <h2 class="card-title"><?php _e('AI Analysis Configuration', 'themewire-security'); ?></h2>
            <p class="description"><?php _e('Configure how the plugin analyzes suspicious files using artificial intelligence.', 'themewire-security'); ?></p>

            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="twss_ai_provider"><?php _e('Primary AI Provider', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <select name="twss_ai_provider" id="twss_ai_provider">
                            <option value="openai" <?php selected($ai_provider, 'openai'); ?>><?php _e('OpenAI (ChatGPT)', 'themewire-security'); ?></option>
                            <option value="gemini" <?php selected($ai_provider, 'gemini'); ?>><?php _e('Google Gemini', 'themewire-security'); ?></option>
                            <option value="openrouter" <?php selected($ai_provider, 'openrouter'); ?>><?php _e('OpenRouter (Multi-Model)', 'themewire-security'); ?></option>
                            <option value="fallback" <?php selected($ai_provider, 'fallback'); ?>><?php _e('Built-in Analysis Only', 'themewire-security'); ?></option>
                        </select>
                        <p class="description"><?php _e('Select your preferred AI provider for malware analysis.', 'themewire-security'); ?></p>
                    </td>
                </tr>

                <tr class="openai-settings" <?php echo $ai_provider !== 'openai' ? 'style="display:none;"' : ''; ?>>
                    <th scope="row">
                        <label><?php _e('OpenAI Authentication', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <div class="auth-options">
                            <div class="auth-option">
                                <h4><?php _e('Option 1: API Key', 'themewire-security'); ?></h4>
                                <input type="text" name="twss_openai_api_key" id="twss_openai_api_key" value="<?php echo esc_attr($openai_api_key); ?>" class="regular-text" placeholder="sk-..." />
                                <button type="button" id="test-openai-api" class="button"><?php _e('Test API Key', 'themewire-security'); ?></button>
                                <span id="openai-api-status"></span>
                                <p class="description"><?php _e('Enter your OpenAI API key. Get one at', 'themewire-security'); ?> <a href="https://platform.openai.com/api-keys" target="_blank">https://platform.openai.com/api-keys</a></p>
                            </div>
                        </div>
                    </td>
                </tr>

                <tr class="gemini-settings" <?php echo $ai_provider !== 'gemini' ? 'style="display:none;"' : ''; ?>>
                    <th scope="row">
                        <label><?php _e('Google Gemini Authentication', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <div class="auth-options">
                            <div class="auth-option">
                                <h4><?php _e('Option 1: API Key', 'themewire-security'); ?></h4>
                                <input type="text" name="twss_gemini_api_key" id="twss_gemini_api_key" value="<?php echo esc_attr($gemini_api_key); ?>" class="regular-text" placeholder="AIza..." />
                                <button type="button" id="test-gemini-api" class="button"><?php _e('Test API Key', 'themewire-security'); ?></button>
                                <span id="gemini-api-status"></span>
                                <p class="description"><?php _e('Enter your Google Gemini API key. Get one at', 'themewire-security'); ?> <a href="https://ai.google.dev/tutorials/setup" target="_blank">https://ai.google.dev/tutorials/setup</a></p>
                            </div>
                        </div>
                    </td>
                </tr>

                <tr class="openrouter-settings" <?php echo $ai_provider !== 'openrouter' ? 'style="display:none;"' : ''; ?>>
                    <th scope="row">
                        <label><?php _e('OpenRouter Authentication', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <div class="auth-section">
                            <div class="auth-method active">
                                <h4><?php _e('API Key', 'themewire-security'); ?></h4>
                                <input type="text" name="twss_openrouter_api_key" id="twss_openrouter_api_key" value="<?php echo esc_attr($openrouter_api_key); ?>" class="regular-text" placeholder="sk-or-..." />
                                <button type="button" id="test-openrouter-api" class="button"><?php _e('Test API Key', 'themewire-security'); ?></button>
                                <br />
                                <span id="openrouter-api-status"></span>
                                <p class="description"><?php _e('Enter your OpenRouter API key. Get one at', 'themewire-security'); ?> <a href="https://openrouter.ai/keys" target="_blank">https://openrouter.ai/keys</a></p>
                                <p class="description"><?php _e('OpenRouter provides access to multiple AI models including Claude, GPT-4, Llama, and more.', 'themewire-security'); ?></p>
                            </div>
                        </div>
                    </td>
                </tr>

                <tr class="openrouter-settings openrouter-model-selection" <?php echo ($ai_provider !== 'openrouter' || empty($openrouter_api_key)) ? 'style="display:none;"' : ''; ?>>
                    <th scope="row">
                        <label for="twss_openrouter_model"><?php _e('OpenRouter Model', 'themewire-security'); ?></label>
                    </th>
                    <td>
                        <select name="twss_openrouter_model" id="twss_openrouter_model" class="regular-text">
                            <?php
                            // Get AI analyzer instance to access models
                            $ai_analyzer = new Themewire_Security_AI_Analyzer();
                            $models = $ai_analyzer->get_openrouter_models();

                            foreach ($models as $model_id => $model_info) {
                                $selected = selected($openrouter_model, $model_id, false);
                                $cost_badge = $model_info['cost'] === 'Free' ? '<span style="color: #46b450; font-weight: bold;">[FREE]</span>' : '<span style="color: #FF7342;">[PAID]</span>';
                                echo "<option value='{$model_id}' {$selected}>{$model_info['name']} {$cost_badge}</option>";
                            }
                            ?>
                        </select>
                        <div id="openrouter-model-info" style="margin-top: 10px; padding: 10px; background: #f9f9f9; border-left: 4px solid #00a0d2; display: none;">
                            <h4 id="model-info-name"></h4>
                            <p id="model-info-description"></p>
                            <p><strong>Cost:</strong> <span id="model-info-cost"></span></p>
                            <p><strong>Context Length:</strong> <span id="model-info-context"></span></p>
                        </div>
                        <p class="description"><?php _e('Choose the AI model for malware analysis. Free models have daily limits but no cost. Paid models offer better performance and higher limits.', 'themewire-security'); ?></p>
                    </td>
                </tr>

                <tr>
                    <th scope="row"><?php _e('Fallback Analysis', 'themewire-security'); ?></th>
                    <td>
                        <label for="twss_use_fallback_ai">
                            <input type="checkbox" name="twss_use_fallback_ai" id="twss_use_fallback_ai" <?php checked($use_fallback_ai); ?> />
                            <?php _e('Use built-in pattern analysis when AI providers are unavailable', 'themewire-security'); ?>
                        </label>
                        <p class="description"><?php _e('If enabled, the plugin will use built-in malware detection patterns when AI services are not accessible.', 'themewire-security'); ?></p>
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
            // Model info data
            var modelInfo = {
                <?php
                $ai_analyzer = new Themewire_Security_AI_Analyzer();
                $models = $ai_analyzer->get_openrouter_models();
                $model_js = array();
                foreach ($models as $model_id => $model_data) {
                    $model_js[] = '"' . $model_id . '": ' . json_encode($model_data);
                }
                echo implode(",\n                ", $model_js);
                ?>
            };

            // Show/hide API key fields based on selected provider
            $('#twss_ai_provider').on('change', function() {
                var provider = $(this).val();

                if (provider === 'openai') {
                    $('.openai-settings').show();
                    $('.gemini-settings').hide();
                    $('.openrouter-settings').hide();
                } else if (provider === 'gemini') {
                    $('.openai-settings').hide();
                    $('.gemini-settings').show();
                    $('.openrouter-settings').hide();
                } else if (provider === 'openrouter') {
                    $('.openai-settings').hide();
                    $('.gemini-settings').hide();
                    $('.openrouter-settings').show();
                    updateModelInfo(); // Show model info when OpenRouter is selected
                } else {
                    $('.openai-settings, .gemini-settings, .openrouter-settings').hide();
                }
            });

            // Update model information when selection changes
            $('#twss_openrouter_model').on('change', function() {
                updateModelInfo();
            });

            // Function to update model information display
            function updateModelInfo() {
                var selectedModel = $('#twss_openrouter_model').val();
                var info = modelInfo[selectedModel];

                if (info) {
                    $('#model-info-name').text(info.name);
                    $('#model-info-description').text(info.description);
                    $('#model-info-cost').text(info.cost);
                    $('#model-info-context').text(info.context);
                    $('#openrouter-model-info').show();
                } else {
                    $('#openrouter-model-info').hide();
                }
            }

            // Initialize model info display if OpenRouter is already selected
            if ($('#twss_ai_provider').val() === 'openrouter') {
                updateModelInfo();
                // If there's already an API key saved, show the model selection
                if ($('#twss_openrouter_api_key').val().trim() !== '') {
                    $('.openrouter-model-selection').show();
                }
            }
        });
    </script>
</div>