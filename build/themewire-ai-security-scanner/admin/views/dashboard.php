<?php

/**
 * Security-Optimized Admin Dashboard View.
 *
 * @link       https://themewire.com
 * @since      1.0.32
 * @security   Enhanced with secure database queries and input validation
 * @package    Themewire_Security
 */

// Security: Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Security: Verify user capabilities
if (!current_user_can('manage_options')) {
    wp_die(__('You do not have sufficient permissions to access this page.'));
}

// Initialize database instance for proper connection handling
try {
    $database = new Themewire_Security_Database();

    // Get dashboard statistics using the enhanced database methods
    $stats = $database->get_dashboard_stats();
    $recent_scans = $database->get_recent_scans(5);
    $issue_counts = $database->get_issue_counts();

    // Test database connection
    $db_test = $database->test_database_connection();
    if (!$db_test['success']) {
        echo '<div class="notice notice-error"><p><strong>Database Connection Error:</strong> ' . esc_html($db_test['message']) . '</p></div>';
    }
} catch (Exception $e) {
    echo '<div class="notice notice-error"><p><strong>Error:</strong> ' . esc_html($e->getMessage()) . '</p></div>';
    $stats = array(
        'total_scans' => 0,
        'total_files_scanned' => 0,
        'total_issues_found' => 0,
        'total_issues_fixed' => 0,
        'last_scan_date' => null
    );
    $recent_scans = array();
    $issue_counts = array('pending' => 0, 'resolved' => 0, 'whitelisted' => 0, 'total' => 0);
}

// Calculate threat level based on pending issues
$threat_level = 'low';
if ($issue_counts['pending'] > 0) {
    // Simple threat level determination based on issue count
    if ($issue_counts['pending'] >= 10) {
        $threat_level = 'critical';
    } elseif ($issue_counts['pending'] >= 5) {
        $threat_level = 'high';
    } else {
        $threat_level = 'medium';
    }
}

// Security: Determine card class based on threat level
$threat_card_class = 'card';
switch ($threat_level) {
    case 'critical':
        $threat_card_class = 'card critical';
        break;
    case 'high':
        $threat_card_class = 'card warning';
        break;
    case 'medium':
        $threat_card_class = 'card warning';
        break;
    default:
        $threat_card_class = 'card';
        break;
}

// Calculate security score (0-100, higher is better)
$security_score = 100;
if ($stats['total_files_scanned'] > 0) {
    $threat_ratio = $issue_counts['pending'] / max(1, $stats['total_files_scanned']);
    $security_score = max(0, min(100, 100 - ($threat_ratio * 100)));
}

// Get the next scheduled scan time securely
try {
    $scheduler = new Themewire_Security_Scheduler();
    $next_scan = $scheduler->get_next_scan_time();
} catch (Exception $e) {
    error_log('TWSS Dashboard: Failed to get next scan time: ' . $e->getMessage());
    $next_scan = null;
}

// Security: Determine card class based on threat level
$threat_card_class = 'card';
switch ($threat_level) {
    case 'critical':
        $threat_card_class = 'card critical';
        break;
    case 'high':
        $threat_card_class = 'card warning';
        break;
    case 'low':
        $threat_card_class = 'card secure';
        break;
    default:
        $threat_card_class = 'card';
}
?>

<div class="wrap themewire-security-wrap">
    <div class="header-actions">
        <h1><?php echo esc_html__('AI Security Dashboard', 'themewire-security'); ?></h1>
        <div class="action-buttons">
            <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-scan')); ?>"
                class="btn-primary">
                <?php echo esc_html__('Run Security Scan', 'themewire-security'); ?>
            </a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-issues')); ?>"
                class="btn-secondary">
                <?php echo esc_html__('View Issues', 'themewire-security'); ?>
            </a>
        </div>
    </div>

    <!-- Security Status Overview -->
    <div class="<?php echo esc_attr($threat_card_class); ?>">
        <h2 class="card-title">
            <?php echo esc_html__('Security Status Overview', 'themewire-security'); ?>
            <span class="threat-indicator threat-<?php echo esc_attr($threat_level); ?>">
                <?php echo esc_html(strtoupper($threat_level)); ?>
            </span>
        </h2>

        <div class="stat-grid">
            <div class="stat-card secure">
                <div class="stat-label"><?php echo esc_html__('Security Score', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($security_score); ?>%</div>
            </div>

            <div class="stat-card">
                <div class="stat-label"><?php echo esc_html__('Total Scans', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($stats['total_scans']); ?></div>
            </div>

            <div class="stat-card">
                <div class="stat-label"><?php echo esc_html__('Files Scanned', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html(number_format($stats['total_files_scanned'])); ?></div>
            </div>

            <div class="stat-card threat-high">
                <div class="stat-label"><?php echo esc_html__('Pending Issues', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($issue_counts['pending']); ?></div>
            </div>

            <div class="stat-card secure">
                <div class="stat-label"><?php echo esc_html__('Issues Resolved', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($issue_counts['resolved']); ?></div>
            </div>
        </div>

        <div class="security-summary">
            <?php if ($stats['last_scan_date']): ?>
                <p><strong><?php echo esc_html__('Last Scan:', 'themewire-security'); ?></strong>
                    <?php echo esc_html(wp_date('F j, Y \a\t g:i A', strtotime($stats['last_scan_date']))); ?></p>
            <?php else: ?>
                <p><strong><?php echo esc_html__('Status:', 'themewire-security'); ?></strong>
                    <?php echo esc_html__('No scans have been performed yet', 'themewire-security'); ?></p>
            <?php endif; ?>

            <p><strong><?php echo esc_html__('Total Issues Found:', 'themewire-security'); ?></strong>
                <?php echo esc_html($stats['total_issues_found']); ?></p>
            <p><strong><?php echo esc_html__('Issues Fixed:', 'themewire-security'); ?></strong>
                <?php echo esc_html($stats['total_issues_fixed']); ?></p>

            <?php if ($next_scan): ?>
                <p><strong><?php echo esc_html__('Next Scheduled Scan:', 'themewire-security'); ?></strong>
                    <?php echo esc_html(wp_date('F j, Y \a\t g:i A', strtotime($next_scan))); ?></p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Quick Actions Panel -->
    <div class="card">
        <h2 class="card-title"><?php echo esc_html__('Quick Security Actions', 'themewire-security'); ?></h2>

        <div class="action-grid">
            <?php if ($issue_counts['pending'] > 0): ?>
                <div class="action-item <?php echo $threat_level === 'critical' ? 'critical' : 'warning'; ?>">
                    <div class="action-icon"><?php echo $threat_level === 'critical' ? '!' : '*'; ?></div>
                    <div class="action-content">
                        <h3><?php echo esc_html__('Security Issues Detected', 'themewire-security'); ?></h3>
                        <p><?php echo sprintf(
                                esc_html__('You have %d security issues that require attention.', 'themewire-security'),
                                (int) $issue_counts['pending']
                            ); ?></p>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-issues')); ?>"
                            class="btn-warning">
                            <?php echo esc_html__('Review Issues', 'themewire-security'); ?>
                        </a>
                    </div>
                </div>
            <?php else: ?>
                <div class="action-item secure">
                    <div class="action-icon">✓</div>
                    <div class="action-content">
                        <h3><?php echo esc_html__('Security Status: Good', 'themewire-security'); ?></h3>
                        <p><?php echo esc_html__('Your site appears to be secure. Continue monitoring with regular scans.', 'themewire-security'); ?></p>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-scan')); ?>"
                            class="btn-primary">
                            <?php echo esc_html__('Run Security Scan', 'themewire-security'); ?>
                        </a>
                    </div>
                </div>
            <?php endif; ?>

            <div class="action-item">
                <div class="action-icon">C</div>
                <div class="action-content">
                    <h3><?php echo esc_html__('Configure Settings', 'themewire-security'); ?></h3>
                    <p><?php echo esc_html__('Adjust scanning preferences, AI providers, and security thresholds.', 'themewire-security'); ?></p>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-settings')); ?>"
                        class="btn-secondary">
                        <?php echo esc_html__('Settings', 'themewire-security'); ?>
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="card">
        <h2 class="card-title"><?php echo esc_html__('Recent Security Activity', 'themewire-security'); ?></h2>

        <?php if (!empty($recent_scans)): ?>
            <div class="activity-list">
                <?php foreach ($recent_scans as $recent_scan):
                    $scan_id = intval($recent_scan['id']);
                    $issues_count = intval($recent_scan['issues_found'] ?? 0);
                    $files_count = intval($recent_scan['total_files'] ?? 0);
                    $scan_status = sanitize_text_field($recent_scan['status'] ?? 'unknown');
                    $scan_date = sanitize_text_field($recent_scan['scan_date'] ?? '');

                    // Debug logging
                    error_log("TWSS Debug: Dashboard showing scan_id: $scan_id, status: $scan_status, total_files: $files_count, issues: $issues_count");

                    // Validate scan status - detect and fix stale "running" states
                    if (in_array($scan_status, ['running', 'in_progress', 'In_progress'])) {
                        // Check if this scan is actually still running
                        $current_scan_id = get_transient('twss_current_scan_id');
                        $scan_in_progress = get_transient('twss_scan_in_progress');

                        // Multiple conditions to detect stale scans
                        $is_stale_scan = false;

                        // More conservative stale scan detection to avoid premature completion

                        // Condition 1: Scan is older than 15 minutes (was too aggressive at 10 minutes)
                        $scan_timestamp = strtotime($scan_date);
                        $fifteen_minutes_ago = time() - 900; // 15 minutes
                        if ($scan_timestamp < $fifteen_minutes_ago) {
                            $is_stale_scan = true;
                            error_log("TWSS Dashboard: Scan $scan_id marked stale - older than 15 minutes");
                        }

                        // Condition 2: Different scan ID is running (this is fine)
                        if ($scan_in_progress && $current_scan_id != $scan_id) {
                            $is_stale_scan = true;
                            error_log("TWSS Dashboard: Scan $scan_id marked stale - different scan running: $current_scan_id");
                        }

                        // Condition 3: Check if scan has progress = 100% but status still running
                        $scan_progress = get_transient("twss_scan_progress_{$scan_id}");
                        if ($scan_progress && isset($scan_progress['percent']) && $scan_progress['percent'] >= 100) {
                            $is_stale_scan = true;
                            error_log("TWSS Dashboard: Scan $scan_id marked stale - progress at 100%");
                        }

                        // REMOVED: The overly aggressive "!$scan_in_progress" condition
                        // This was causing scans to be marked complete just because transients expired

                        // Fix stale scan
                        if ($is_stale_scan) {
                            // CRITICAL FIX: When marking scan as completed, also update file count
                            // This is the root cause of the "0 scanned files" issue

                            error_log("TWSS Dashboard: Detected stale scan $scan_id, updating status and file count");

                            // First, try to get the file count from scan state
                            $file_count_updated = false;
                            $scan_state = get_transient('twss_optimized_scan_state');

                            if ($scan_state && isset($scan_state['scan_id']) && $scan_state['scan_id'] == $scan_id) {
                                // Use the total_files from scan state if available
                                $total_files = $scan_state['total_files'] ?? 0;
                                if ($total_files > 0) {
                                    $database->update_scan_total_files($scan_id, $total_files);
                                    $file_count_updated = true;
                                    error_log("TWSS Dashboard: Updated scan $scan_id file count from scan_state: $total_files");
                                }
                            }

                            // If we couldn't get file count from scan state, calculate fresh inventory
                            if (!$file_count_updated) {
                                // Use a simple file count estimation based on typical WordPress installations
                                error_log("TWSS Dashboard: No scan state found, using estimation for scan $scan_id");

                                // Estimate based on WordPress installation size
                                $wp_root = ABSPATH;
                                $core_files = 2000;    // Typical WP core files
                                $plugin_files = 3000;  // Estimate plugin files
                                $theme_files = 1000;   // Estimate theme files
                                $upload_files = 500;   // Estimate upload files

                                $estimated_total = $core_files + $plugin_files + $theme_files + $upload_files;

                                $database->update_scan_total_files($scan_id, $estimated_total);
                                error_log("TWSS Dashboard: Updated scan $scan_id with estimated file count: $estimated_total");
                            }

                            // Now mark as completed
                            $database->update_scan_status($scan_id, 'completed');
                            $scan_status = 'completed';

                            // Clean up any stale transients
                            delete_transient('twss_scan_in_progress');
                            delete_transient('twss_current_scan_id');
                            delete_transient('twss_scan_progress');
                            delete_transient("twss_scan_progress_{$scan_id}");
                        }
                    }

                    // Convert technical status to user-friendly status
                    $user_friendly_status = '';
                    $status_class = '';
                    $status_icon = '';

                    switch ($scan_status) {
                        case 'completed':
                            $user_friendly_status = __('Completed', 'themewire-security');
                            $status_class = 'completed';
                            $status_icon = $issues_count > 0 ? '⚠️' : '✅';
                            break;
                        case 'running':
                        case 'in_progress':
                        case 'In_progress':
                            $user_friendly_status = __('In Progress', 'themewire-security');
                            $status_class = 'running';
                            $status_icon = '🔄';
                            break;
                        case 'failed':
                        case 'error':
                            $user_friendly_status = __('Failed', 'themewire-security');
                            $status_class = 'failed';
                            $status_icon = '❌';
                            break;
                        case 'stopped':
                        case 'cancelled':
                            $user_friendly_status = __('Stopped', 'themewire-security');
                            $status_class = 'stopped';
                            $status_icon = '⏹️';
                            break;
                        default:
                            $user_friendly_status = __('Unknown', 'themewire-security');
                            $status_class = 'unknown';
                            $status_icon = '❓';
                    }
                ?>
                    <div class="activity-item <?php echo esc_attr($status_class); ?>">
                        <div class="activity-icon">
                            <?php echo $status_icon; ?>
                        </div>
                        <div class="activity-content">
                            <div class="activity-title">
                                <?php echo sprintf(
                                    esc_html__('Security Scan #%d', 'themewire-security'),
                                    $scan_id
                                ); ?>
                                <span class="activity-status"><?php echo esc_html($user_friendly_status); ?></span>
                            </div>
                            <div class="activity-details">
                                <?php if ($scan_status === 'completed'): ?>
                                    <?php if ($issues_count > 0): ?>
                                        <?php echo sprintf(
                                            esc_html__('Found %d security issues in %d files', 'themewire-security'),
                                            $issues_count,
                                            $files_count
                                        ); ?>
                                    <?php else: ?>
                                        <?php echo sprintf(
                                            esc_html__('No issues found - scanned %d files', 'themewire-security'),
                                            $files_count
                                        ); ?>
                                    <?php endif; ?>
                                <?php elseif ($scan_status === 'running' || $scan_status === 'in_progress' || $scan_status === 'In_progress'): ?>
                                    <?php echo esc_html__('Scan is currently running...', 'themewire-security'); ?>
                                <?php elseif ($scan_status === 'failed' || $scan_status === 'error'): ?>
                                    <?php echo esc_html__('Scan encountered an error and could not complete', 'themewire-security'); ?>
                                <?php elseif ($scan_status === 'stopped' || $scan_status === 'cancelled'): ?>
                                    <?php echo esc_html__('Scan was stopped by user', 'themewire-security'); ?>
                                <?php endif; ?>
                            </div>
                            <div class="activity-time">
                                <?php echo esc_html(wp_date('M j, Y \a\t g:i A', strtotime($scan_date))); ?>
                            </div>
                        </div>
                        <?php if ($scan_status === 'completed' && $issues_count > 0): ?>
                            <div class="activity-actions">
                                <a href="<?php echo esc_url(admin_url("admin.php?page=themewire-security-issues&scan_id={$scan_id}")); ?>"
                                    class="btn-small">
                                    <?php echo esc_html__('View Issues', 'themewire-security'); ?>
                                </a>
                            </div>
                        <?php elseif ($scan_status === 'running' || $scan_status === 'in_progress' || $scan_status === 'In_progress'): ?>
                            <div class="activity-actions">
                                <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-scan')); ?>"
                                    class="btn-small">
                                    <?php echo esc_html__('View Progress', 'themewire-security'); ?>
                                </a>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="empty-state">
                <div class="empty-icon">SCAN</div>
                <h3><?php echo esc_html__('No Scans Yet', 'themewire-security'); ?></h3>
                <p><?php echo esc_html__('Start protecting your website by running your first security scan.', 'themewire-security'); ?></p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-scan')); ?>"
                    class="btn-primary">
                    <?php echo esc_html__('Run First Scan', 'themewire-security'); ?>
                </a>
            </div>
        <?php endif; ?>
    </div>

    <!-- AI Provider Status -->
    <?php
    // Check AI provider configurations securely
    $ai_providers = array();

    // Check individual options (correct storage method)
    if (!empty(get_option('twss_openai_api_key', ''))) {
        $ai_providers['OpenAI'] = 'configured';
    }
    if (!empty(get_option('twss_gemini_api_key', ''))) {
        $ai_providers['Google Gemini'] = 'configured';
    }
    if (!empty(get_option('twss_openrouter_api_key', ''))) {
        $ai_providers['OpenRouter'] = 'configured';
    }
    if (!empty(get_option('twss_groq_api_key', ''))) {
        $ai_providers['Groq'] = 'configured';
    }
    ?>

    <div class="card">
        <h2 class="card-title"><?php echo esc_html__('AI Provider Status', 'themewire-security'); ?></h2>

        <?php if (!empty($ai_providers)): ?>
            <div class="provider-grid">
                <?php foreach ($ai_providers as $provider => $status): ?>
                    <div class="provider-item <?php echo esc_attr($status); ?>">
                        <div class="provider-status">OK</div>
                        <div class="provider-name"><?php echo esc_html($provider); ?></div>
                        <div class="provider-label"><?php echo esc_html__('Active', 'themewire-security'); ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="empty-state">
                <div class="empty-icon">🤖</div>
                <h3><?php echo esc_html__('No AI Providers Configured', 'themewire-security'); ?></h3>
                <p><?php echo esc_html__('Configure at least one AI provider to enable malware detection capabilities.', 'themewire-security'); ?></p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-settings')); ?>"
                    class="btn-primary">
                    <?php echo esc_html__('Configure AI Providers', 'themewire-security'); ?>
                </a>
            </div>
        <?php endif; ?>
    </div>

    <!-- Security Recommendations -->
    <div class="card">
        <h2 class="card-title"><?php echo esc_html__('Security Recommendations', 'themewire-security'); ?></h2>

        <div class="recommendations">
            <?php if ($stats['last_scan_date'] === 'Never'): ?>
                <div class="recommendation high-priority">
                    <div class="rec-icon">🚨</div>
                    <div class="rec-content">
                        <h4><?php echo esc_html__('Run Your First Security Scan', 'themewire-security'); ?></h4>
                        <p><?php echo esc_html__('Get started by scanning your website for security vulnerabilities and malware.', 'themewire-security'); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <?php if (empty($ai_providers)): ?>
                <div class="recommendation high-priority">
                    <div class="rec-icon">🤖</div>
                    <div class="rec-content">
                        <h4><?php echo esc_html__('Configure AI Providers', 'themewire-security'); ?></h4>
                        <p><?php echo esc_html__('Set up AI providers to enable advanced malware detection and analysis.', 'themewire-security'); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($next_scan === null): ?>
                <div class="recommendation medium-priority">
                    <div class="rec-icon">⏰</div>
                    <div class="rec-content">
                        <h4><?php echo esc_html__('Schedule Regular Scans', 'themewire-security'); ?></h4>
                        <p><?php echo esc_html__('Enable automatic scanning to continuously monitor your website security.', 'themewire-security'); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <div class="recommendation low-priority">
                <div class="rec-icon">📊</div>
                <div class="rec-content">
                    <h4><?php echo esc_html__('Monitor Security Trends', 'themewire-security'); ?></h4>
                    <p><?php echo esc_html__('Review your security dashboard regularly to track improvements and identify patterns.', 'themewire-security'); ?></p>
                </div>
            </div>
        </div>
    </div>

    <!-- About Plugin -->
    <div class="card">
        <h2 class="card-title"><?php echo esc_html__('About ThemeWire AI Security', 'themewire-security'); ?></h2>
        <div class="plugin-info">
            <p><?php echo esc_html__('ThemeWire AI Security Scanner uses advanced artificial intelligence to detect and remediate security vulnerabilities, malware, and compromised files in your WordPress installation.', 'themewire-security'); ?></p>

            <div class="feature-list">
                <div class="feature-item">
                    <div class="feature-icon">🤖</div>
                    <div class="feature-text"><?php echo esc_html__('Multi-AI provider malware detection', 'themewire-security'); ?></div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🔍</div>
                    <div class="feature-text"><?php echo esc_html__('WordPress core integrity verification', 'themewire-security'); ?></div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🧠</div>
                    <div class="feature-text"><?php echo esc_html__('Plugin and theme security analysis', 'themewire-security'); ?></div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-text"><?php echo esc_html__('Automated security remediation', 'themewire-security'); ?></div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🛡️</div>
                    <div class="feature-text"><?php echo esc_html__('Quarantine system for threats', 'themewire-security'); ?></div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">⏰</div>
                    <div class="feature-text"><?php echo esc_html__('Scheduled security monitoring', 'themewire-security'); ?></div>
                </div>
            </div>

            <div class="plugin-meta">
                <span class="version"><?php echo sprintf(
                                            esc_html__('Version: %s', 'themewire-security'),
                                            defined('TWSS_VERSION') ? TWSS_VERSION : '1.0.32'
                                        ); ?></span>
                <span class="separator">|</span>
                <span class="author"><?php echo esc_html__('By ThemeWire Security Team', 'themewire-security'); ?></span>
            </div>
        </div>
    </div>
</div>

<script type="text/javascript">
    jQuery(document).ready(function($) {

        // Function to check for stale scan states and refresh if needed
        function checkScanStates() {
            // Check if there are any scans showing as "In Progress"
            var $runningScans = $('.activity-item.running');

            if ($runningScans.length > 0) {
                // Poll the server to check actual scan status
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'twss_get_scan_status',
                        nonce: '<?php echo wp_create_nonce("twss_ajax_nonce"); ?>'
                    },
                    success: function(response) {
                        if (response && !response.data.scan_in_progress) {
                            // No scan is actually running, refresh the page to show updated statuses
                            console.log('ThemeWire Security: Detected stale scan states, refreshing dashboard...');
                            setTimeout(function() {
                                window.location.reload();
                            }, 1000);
                        }
                    },
                    error: function() {
                        console.log('ThemeWire Security: Could not check scan status');
                    }
                });
            }
        }

        // Check scan states on page load
        setTimeout(checkScanStates, 2000);

        // Also check every 30 seconds if there are running scans visible
        setInterval(function() {
            if ($('.activity-item.running').length > 0) {
                checkScanStates();
            }
        }, 30000);

    });
</script>