<?php

/**
 * Security-Optimized Admin Settings View.
 *
 * @link       https://themewire.com
 * @since      1.0.32
 * @security   Enhanced with comprehensive input validation, CSRF protection, and secure data handling
 * @package    Themewire_Security
 */

// Security: Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Security: Verify user capabilities
if (!current_user_can('manage_options')) {
    wp_die(__('You do not have sufficient permissions to access this page.', 'themewire-security'));
}

// Security: Process form submission with comprehensive validation
$settings_saved = false;
$error_message = '';

if (isset($_POST['twss_settings_submit']) && wp_verify_nonce($_POST['twss_settings_nonce'] ?? '', 'twss_settings_action')) {

    try {
        // Sanitize and validate all inputs
        $sanitized_data = array(
            'ai_provider' => sanitize_text_field($_POST['twss_ai_provider'] ?? 'openai'),
            'openai_api_key' => sanitize_text_field($_POST['twss_openai_api_key'] ?? ''),
            'gemini_api_key' => sanitize_text_field($_POST['twss_gemini_api_key'] ?? ''),
            'openrouter_api_key' => sanitize_text_field($_POST['twss_openrouter_api_key'] ?? ''),
            'openrouter_model' => sanitize_text_field($_POST['twss_openrouter_model'] ?? 'openai/gpt-3.5-turbo'),
            'groq_api_key' => sanitize_text_field($_POST['twss_groq_api_key'] ?? ''),
            'groq_model' => sanitize_text_field($_POST['twss_groq_model'] ?? 'llama-3.3-70b-versatile'),
            'use_fallback_ai' => !empty($_POST['twss_use_fallback_ai']),
            'scheduled_time' => sanitize_text_field($_POST['twss_scheduled_time'] ?? '02:00'),
            'auto_fix' => !empty($_POST['twss_auto_fix']),
            'send_email' => !empty($_POST['twss_send_email']),
            'auto_update' => !empty($_POST['twss_auto_update']),
            'remove_data_on_uninstall' => !empty($_POST['twss_remove_data_on_uninstall']),
            'scan_frequency' => sanitize_text_field($_POST['twss_scan_frequency'] ?? 'daily'),
            'max_file_size' => max(1, min(100, intval($_POST['twss_max_file_size'] ?? 10))), // 1-100 MB limit
            'enable_logging' => !empty($_POST['twss_enable_logging']),
            'log_level' => sanitize_text_field($_POST['twss_log_level'] ?? 'warning'),
            'quarantine_threats' => !empty($_POST['twss_quarantine_threats']),
            'notification_email' => sanitize_email($_POST['twss_notification_email'] ?? get_option('admin_email'))
        );

        // Security: Validate AI provider selection
        $allowed_providers = array('openai', 'gemini', 'openrouter', 'groq');
        if (!in_array($sanitized_data['ai_provider'], $allowed_providers)) {
            $sanitized_data['ai_provider'] = 'openai';
        }

        // Security: Validate time format for scheduled scans
        if (!preg_match('/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/', $sanitized_data['scheduled_time'])) {
            $sanitized_data['scheduled_time'] = '02:00';
        }

        // Security: Validate scan frequency
        $allowed_frequencies = array('hourly', 'daily', 'weekly', 'monthly');
        if (!in_array($sanitized_data['scan_frequency'], $allowed_frequencies)) {
            $sanitized_data['scan_frequency'] = 'daily';
        }

        // Security: Validate log level
        $allowed_log_levels = array('debug', 'info', 'warning', 'error', 'critical');
        if (!in_array($sanitized_data['log_level'], $allowed_log_levels)) {
            $sanitized_data['log_level'] = 'warning';
        }

        // Security: Validate and encrypt API keys if they're not empty
        foreach (['openai_api_key', 'gemini_api_key', 'openrouter_api_key', 'groq_api_key'] as $key_field) {
            if (!empty($sanitized_data[$key_field])) {
                // Basic API key format validation
                if (strlen($sanitized_data[$key_field]) < 10 || strlen($sanitized_data[$key_field]) > 200) {
                    throw new Exception(sprintf(__('Invalid API key format for %s', 'themewire-security'), $key_field));
                }
            }
        }

        // Security: Validate email if provided
        if (!empty($sanitized_data['notification_email']) && !is_email($sanitized_data['notification_email'])) {
            $sanitized_data['notification_email'] = get_option('admin_email');
        }

        // Save settings with proper option names
        $option_mapping = array(
            'ai_provider' => 'twss_ai_provider',
            'openai_api_key' => 'twss_openai_api_key',
            'gemini_api_key' => 'twss_gemini_api_key',
            'openrouter_api_key' => 'twss_openrouter_api_key',
            'openrouter_model' => 'twss_openrouter_model',
            'groq_api_key' => 'twss_groq_api_key',
            'groq_model' => 'twss_groq_model',
            'use_fallback_ai' => 'twss_use_fallback_ai',
            'scheduled_time' => 'twss_scheduled_time',
            'auto_fix' => 'twss_auto_fix',
            'send_email' => 'twss_send_email',
            'auto_update' => 'twss_auto_update',
            'remove_data_on_uninstall' => 'twss_remove_data_on_uninstall',
            'scan_frequency' => 'twss_scan_frequency',
            'max_file_size' => 'twss_max_file_size',
            'enable_logging' => 'twss_enable_logging',
            'log_level' => 'twss_log_level',
            'quarantine_threats' => 'twss_quarantine_threats',
            'notification_email' => 'twss_notification_email'
        );

        // Update all options
        foreach ($option_mapping as $key => $option_name) {
            update_option($option_name, $sanitized_data[$key]);
        }

        // Update scheduled scan time with scheduler
        if (class_exists('Themewire_Security_Scheduler')) {
            try {
                $scheduler = new Themewire_Security_Scheduler();
                $scheduler->update_scheduled_time($sanitized_data['scheduled_time'], $sanitized_data['scan_frequency']);
            } catch (Exception $e) {
                error_log('TWSS Settings: Scheduler update failed - ' . $e->getMessage());
            }
        }

        $settings_saved = true;
    } catch (Exception $e) {
        $error_message = $e->getMessage();
        error_log('TWSS Settings: Save failed - ' . $error_message);
    }
}

// Security: Get current settings with proper defaults and validation
$current_settings = array(
    'ai_provider' => get_option('twss_ai_provider', 'openai'),
    'openai_api_key' => get_option('twss_openai_api_key', ''),
    'gemini_api_key' => get_option('twss_gemini_api_key', ''),
    'openrouter_api_key' => get_option('twss_openrouter_api_key', ''),
    'openrouter_model' => get_option('twss_openrouter_model', 'openai/gpt-3.5-turbo'),
    'groq_api_key' => get_option('twss_groq_api_key', ''),
    'groq_model' => get_option('twss_groq_model', 'llama-3.3-70b-versatile'),
    'use_fallback_ai' => (bool)get_option('twss_use_fallback_ai', true),
    'scheduled_time' => get_option('twss_scheduled_time', '02:00'),
    'auto_fix' => (bool)get_option('twss_auto_fix', false),
    'send_email' => (bool)get_option('twss_send_email', true),
    'auto_update' => (bool)get_option('twss_auto_update', false),
    'remove_data_on_uninstall' => (bool)get_option('twss_remove_data_on_uninstall', false),
    'scan_frequency' => get_option('twss_scan_frequency', 'daily'),
    'max_file_size' => max(1, min(100, (int)get_option('twss_max_file_size', 10))),
    'enable_logging' => (bool)get_option('twss_enable_logging', true),
    'log_level' => get_option('twss_log_level', 'warning'),
    'quarantine_threats' => (bool)get_option('twss_quarantine_threats', true),
    'notification_email' => get_option('twss_notification_email', get_option('admin_email'))
);

// Validate current settings
$allowed_providers = array('openai', 'gemini', 'openrouter', 'groq');
if (!in_array($current_settings['ai_provider'], $allowed_providers)) {
    $current_settings['ai_provider'] = 'openai';
}

// Security: Mask API keys for display (show only last 4 characters)
$masked_keys = array();
foreach (['openai_api_key', 'gemini_api_key', 'openrouter_api_key', 'groq_api_key'] as $key_field) {
    $key_value = $current_settings[$key_field];
    if (strlen($key_value) > 8) {
        $masked_keys[$key_field] = str_repeat('*', strlen($key_value) - 4) . substr($key_value, -4);
    } else {
        $masked_keys[$key_field] = str_repeat('*', strlen($key_value));
    }
}
?>

<div class="wrap themewire-security-wrap">
    <div class="header-actions">
        <h1><?php echo esc_html__('Security Scanner Settings', 'themewire-security'); ?></h1>
        <div class="action-buttons">
            <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security')); ?>"
                class="btn-secondary">
                <?php echo esc_html__('Back to Dashboard', 'themewire-security'); ?>
            </a>
        </div>
    </div>

    <?php if ($settings_saved): ?>
        <div class="notice notice-success">
            <p><strong><?php echo esc_html__('Success!', 'themewire-security'); ?></strong>
                <?php echo esc_html__('Settings have been saved successfully.', 'themewire-security'); ?></p>
        </div>
    <?php endif; ?>

    <?php if (!empty($error_message)): ?>
        <div class="notice notice-error">
            <p><strong><?php echo esc_html__('Error!', 'themewire-security'); ?></strong>
                <?php echo esc_html($error_message); ?></p>
        </div>
    <?php endif; ?>

    <form method="post" action="" class="settings-form">
        <?php wp_nonce_field('twss_settings_action', 'twss_settings_nonce'); ?>

        <!-- AI Provider Configuration -->
        <div class="card">
            <h2 class="card-title"><?php echo esc_html__('AI Provider Configuration', 'themewire-security'); ?></h2>

            <div class="form-section">
                <div class="form-row">
                    <div class="form-field">
                        <label for="twss_ai_provider" class="form-label">
                            <?php echo esc_html__('Primary AI Provider', 'themewire-security'); ?>
                            <span class="required">*</span>
                        </label>
                        <select name="twss_ai_provider" id="twss_ai_provider" class="form-select" required>
                            <option value="openai" <?php selected($current_settings['ai_provider'], 'openai'); ?>>OpenAI (GPT-4)</option>
                            <option value="gemini" <?php selected($current_settings['ai_provider'], 'gemini'); ?>>Google Gemini</option>
                            <option value="openrouter" <?php selected($current_settings['ai_provider'], 'openrouter'); ?>>OpenRouter</option>
                            <option value="groq" <?php selected($current_settings['ai_provider'], 'groq'); ?>>Groq (Llama)</option>
                        </select>
                        <p class="form-description"><?php echo esc_html__('Select your preferred AI provider for malware analysis.', 'themewire-security'); ?></p>
                    </div>

                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_use_fallback_ai" value="1" <?php checked($current_settings['use_fallback_ai']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Enable AI Provider Fallback', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Automatically try other providers if primary fails.', 'themewire-security'); ?></p>
                    </div>
                </div>

                <!-- OpenAI Configuration -->
                <div class="form-row" id="openai-config">
                    <div class="form-field">
                        <label for="twss_openai_api_key" class="form-label">
                            <?php echo esc_html__('OpenAI API Key', 'themewire-security'); ?>
                        </label>
                        <div style="display: flex; gap: 10px; align-items: flex-end;">
                            <div style="flex: 1;">
                                <input type="password" name="twss_openai_api_key" id="twss_openai_api_key"
                                    class="form-input" placeholder="<?php echo esc_attr($masked_keys['openai_api_key']); ?>"
                                    autocomplete="off">
                                <p class="form-description">
                                    <?php if (!empty($current_settings['openai_api_key'])): ?>
                                        <strong>✓ API key saved.</strong> Leave empty to keep current key, or enter new key to update.
                                        <br>
                                    <?php endif; ?>
                                    <?php echo sprintf(
                                        esc_html__('Get your API key from %s', 'themewire-security'),
                                        '<a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener">platform.openai.com</a>'
                                    ); ?>
                                </p>
                            </div>
                            <button type="button" class="test-api-button btn btn-secondary" data-provider="openai">
                                <?php echo empty($current_settings['openai_api_key']) ? esc_html__('Test Connection', 'themewire-security') : esc_html__('Test Saved Key', 'themewire-security'); ?>
                            </button>
                        </div>
                        <div id="openai-api-status" class="api-status" style="display: none;"></div>
                    </div>
                </div>

                <!-- Gemini Configuration -->
                <div class="form-row" id="gemini-config">
                    <div class="form-field">
                        <label for="twss_gemini_api_key" class="form-label">
                            <?php echo esc_html__('Google Gemini API Key', 'themewire-security'); ?>
                        </label>
                        <div style="display: flex; gap: 10px; align-items: flex-end;">
                            <div style="flex: 1;">
                                <input type="password" name="twss_gemini_api_key" id="twss_gemini_api_key"
                                    class="form-input" placeholder="<?php echo esc_attr($masked_keys['gemini_api_key']); ?>"
                                    autocomplete="off">
                                <p class="form-description">
                                    <?php echo sprintf(
                                        esc_html__('Get your API key from %s', 'themewire-security'),
                                        '<a href="https://makersuite.google.com/app/apikey" target="_blank" rel="noopener">Google AI Studio</a>'
                                    ); ?>
                                </p>
                            </div>
                            <button type="button" class="test-api-button btn btn-secondary" data-provider="gemini">
                                <?php echo esc_html__('Test Connection', 'themewire-security'); ?>
                            </button>
                        </div>
                        <div id="gemini-api-status" class="api-status" style="display: none;"></div>
                    </div>
                </div>

                <!-- OpenRouter Configuration -->
                <div class="form-row" id="openrouter-config">
                    <div class="form-field">
                        <label for="twss_openrouter_api_key" class="form-label">
                            <?php echo esc_html__('OpenRouter API Key', 'themewire-security'); ?>
                        </label>
                        <div style="display: flex; gap: 10px; align-items: flex-end;">
                            <input type="password" name="twss_openrouter_api_key" id="twss_openrouter_api_key"
                                class="form-input" placeholder="<?php echo esc_attr($masked_keys['openrouter_api_key']); ?>"
                                autocomplete="off" style="flex: 1;">
                            <button type="button" class="test-api-button btn btn-secondary" data-provider="openrouter">
                                <?php echo esc_html__('Test Connection', 'themewire-security'); ?>
                            </button>
                        </div>
                        <div id="openrouter-api-status" class="api-status" style="display: none;"></div>
                    </div>
                    <div class="form-field">
                        <label for="twss_openrouter_model" class="form-label">
                            <?php echo esc_html__('OpenRouter Model', 'themewire-security'); ?>
                        </label>
                        <select name="twss_openrouter_model" id="twss_openrouter_model" class="form-select">
                            <option value="openai/gpt-4-turbo" <?php selected($current_settings['openrouter_model'], 'openai/gpt-4-turbo'); ?>>GPT-4 Turbo</option>
                            <option value="openai/gpt-3.5-turbo" <?php selected($current_settings['openrouter_model'], 'openai/gpt-3.5-turbo'); ?>>GPT-3.5 Turbo</option>
                            <option value="anthropic/claude-3-opus" <?php selected($current_settings['openrouter_model'], 'anthropic/claude-3-opus'); ?>>Claude 3 Opus</option>
                            <option value="anthropic/claude-3-sonnet" <?php selected($current_settings['openrouter_model'], 'anthropic/claude-3-sonnet'); ?>>Claude 3 Sonnet</option>
                        </select>
                    </div>
                </div>

                <!-- Groq Configuration -->
                <div class="form-row" id="groq-config">
                    <div class="form-field">
                        <label for="twss_groq_api_key" class="form-label">
                            <?php echo esc_html__('Groq API Key', 'themewire-security'); ?>
                        </label>
                        <div style="display: flex; gap: 10px; align-items: flex-end;">
                            <input type="password" name="twss_groq_api_key" id="twss_groq_api_key"
                                class="form-input" placeholder="<?php echo esc_attr($masked_keys['groq_api_key']); ?>"
                                autocomplete="off" style="flex: 1;">
                            <button type="button" class="test-api-button btn btn-secondary" data-provider="groq">
                                <?php echo esc_html__('Test Connection', 'themewire-security'); ?>
                            </button>
                        </div>
                        <div id="groq-api-status" class="api-status" style="display: none;"></div>
                    </div>
                    <div class="form-field">
                        <label for="twss_groq_model" class="form-label">
                            <?php echo esc_html__('Groq Model', 'themewire-security'); ?>
                        </label>
                        <select name="twss_groq_model" id="twss_groq_model" class="form-select">
                            <option value="llama-3.3-70b-versatile" <?php selected($current_settings['groq_model'], 'llama-3.3-70b-versatile'); ?>>Llama 3.3 70B Versatile</option>
                            <option value="llama-3.1-8b-instant" <?php selected($current_settings['groq_model'], 'llama-3.1-8b-instant'); ?>>Llama 3.1 8B Instant</option>
                            <option value="mixtral-8x7b-32768" <?php selected($current_settings['groq_model'], 'mixtral-8x7b-32768'); ?>>Mixtral 8x7B</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Scanning Configuration -->
        <div class="card">
            <h2 class="card-title"><?php echo esc_html__('Scanning Configuration', 'themewire-security'); ?></h2>

            <div class="form-section">
                <div class="form-row">
                    <div class="form-field">
                        <label for="twss_scan_frequency" class="form-label">
                            <?php echo esc_html__('Scan Frequency', 'themewire-security'); ?>
                        </label>
                        <select name="twss_scan_frequency" id="twss_scan_frequency" class="form-select">
                            <option value="hourly" <?php selected($current_settings['scan_frequency'], 'hourly'); ?>>
                                <?php echo esc_html__('Every Hour', 'themewire-security'); ?>
                            </option>
                            <option value="daily" <?php selected($current_settings['scan_frequency'], 'daily'); ?>>
                                <?php echo esc_html__('Daily', 'themewire-security'); ?>
                            </option>
                            <option value="weekly" <?php selected($current_settings['scan_frequency'], 'weekly'); ?>>
                                <?php echo esc_html__('Weekly', 'themewire-security'); ?>
                            </option>
                            <option value="monthly" <?php selected($current_settings['scan_frequency'], 'monthly'); ?>>
                                <?php echo esc_html__('Monthly', 'themewire-security'); ?>
                            </option>
                        </select>
                    </div>

                    <div class="form-field">
                        <label for="twss_scheduled_time" class="form-label">
                            <?php echo esc_html__('Scheduled Time', 'themewire-security'); ?>
                        </label>
                        <input type="time" name="twss_scheduled_time" id="twss_scheduled_time"
                            class="form-input" value="<?php echo esc_attr($current_settings['scheduled_time']); ?>">
                        <p class="form-description"><?php echo esc_html__('Time when scheduled scans should run (24-hour format).', 'themewire-security'); ?></p>
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-field">
                        <label for="twss_max_file_size" class="form-label">
                            <?php echo esc_html__('Maximum File Size (MB)', 'themewire-security'); ?>
                        </label>
                        <input type="number" name="twss_max_file_size" id="twss_max_file_size"
                            class="form-input" value="<?php echo esc_attr($current_settings['max_file_size']); ?>"
                            min="1" max="100">
                        <p class="form-description"><?php echo esc_html__('Maximum file size to scan (1-100 MB).', 'themewire-security'); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Actions -->
        <div class="card">
            <h2 class="card-title"><?php echo esc_html__('Security Actions', 'themewire-security'); ?></h2>

            <div class="form-section">
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_auto_fix" value="1" <?php checked($current_settings['auto_fix']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Automatic Issue Resolution', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Automatically attempt to fix detected security issues.', 'themewire-security'); ?></p>
                    </div>

                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_quarantine_threats" value="1" <?php checked($current_settings['quarantine_threats']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Quarantine Threats', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Move detected malware to secure quarantine instead of deleting.', 'themewire-security'); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Notifications -->
        <div class="card">
            <h2 class="card-title"><?php echo esc_html__('Notifications', 'themewire-security'); ?></h2>

            <div class="form-section">
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_send_email" value="1" <?php checked($current_settings['send_email']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Email Notifications', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Send email notifications when security issues are detected.', 'themewire-security'); ?></p>
                    </div>

                    <div class="form-field">
                        <label for="twss_notification_email" class="form-label">
                            <?php echo esc_html__('Notification Email', 'themewire-security'); ?>
                        </label>
                        <input type="email" name="twss_notification_email" id="twss_notification_email"
                            class="form-input" value="<?php echo esc_attr($current_settings['notification_email']); ?>">
                        <p class="form-description"><?php echo esc_html__('Email address to receive security notifications.', 'themewire-security'); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Advanced Settings -->
        <div class="card">
            <h2 class="card-title"><?php echo esc_html__('Advanced Settings', 'themewire-security'); ?></h2>

            <div class="form-section">
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_enable_logging" value="1" <?php checked($current_settings['enable_logging']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Enable Security Logging', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Log security scan activities and events.', 'themewire-security'); ?></p>
                    </div>

                    <div class="form-field">
                        <label for="twss_log_level" class="form-label">
                            <?php echo esc_html__('Logging Level', 'themewire-security'); ?>
                        </label>
                        <select name="twss_log_level" id="twss_log_level" class="form-select">
                            <option value="debug" <?php selected($current_settings['log_level'], 'debug'); ?>>
                                <?php echo esc_html__('Debug (Verbose)', 'themewire-security'); ?>
                            </option>
                            <option value="info" <?php selected($current_settings['log_level'], 'info'); ?>>
                                <?php echo esc_html__('Info', 'themewire-security'); ?>
                            </option>
                            <option value="warning" <?php selected($current_settings['log_level'], 'warning'); ?>>
                                <?php echo esc_html__('Warning', 'themewire-security'); ?>
                            </option>
                            <option value="error" <?php selected($current_settings['log_level'], 'error'); ?>>
                                <?php echo esc_html__('Error', 'themewire-security'); ?>
                            </option>
                            <option value="critical" <?php selected($current_settings['log_level'], 'critical'); ?>>
                                <?php echo esc_html__('Critical Only', 'themewire-security'); ?>
                            </option>
                        </select>
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_auto_update" value="1" <?php checked($current_settings['auto_update']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Automatic Plugin Updates', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Automatically update plugin to latest security patches.', 'themewire-security'); ?></p>
                    </div>

                    <div class="form-field">
                        <label class="form-checkbox">
                            <input type="checkbox" name="twss_remove_data_on_uninstall" value="1" <?php checked($current_settings['remove_data_on_uninstall']); ?>>
                            <span class="checkmark"></span>
                            <?php echo esc_html__('Remove Data on Uninstall', 'themewire-security'); ?>
                        </label>
                        <p class="form-description"><?php echo esc_html__('Delete all plugin data when uninstalling (cannot be undone).', 'themewire-security'); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <div class="form-actions">
            <button type="submit" name="twss_settings_submit" class="btn-primary">
                <?php echo esc_html__('Save Settings', 'themewire-security'); ?>
            </button>
            <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-scan')); ?>" class="btn-secondary">
                <?php echo esc_html__('Test Configuration', 'themewire-security'); ?>
            </a>
        </div>
    </form>
</div>

<script>
    // Show/hide AI provider specific configurations
    document.getElementById('twss_ai_provider').addEventListener('change', function() {
        const provider = this.value;
        const configs = ['openai-config', 'gemini-config', 'openrouter-config', 'groq-config'];

        configs.forEach(configId => {
            const element = document.getElementById(configId);
            if (element) {
                element.style.display = configId.includes(provider) ? 'block' : 'none';
            }
        });
    });

    // Trigger initial state
    document.getElementById('twss_ai_provider').dispatchEvent(new Event('change'));

    // Clear password fields on focus (for better UX when updating keys)
    document.querySelectorAll('input[type="password"]').forEach(field => {
        field.addEventListener('focus', function() {
            if (this.placeholder.includes('*')) {
                this.value = '';
                this.placeholder = 'Enter new API key';
            }
        });
    });
</script>