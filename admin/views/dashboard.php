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

// Get the most recent scan with prepared statement
global $wpdb;
$scan = $wpdb->get_row($wpdb->prepare(
    "SELECT * FROM {$wpdb->prefix}twss_scans ORDER BY scan_date DESC LIMIT %d",
    1
), ARRAY_A);

// Initialize secure stats array
$stats = array(
    'total_issues' => 0,
    'high_severity' => 0,
    'medium_severity' => 0,
    'low_severity' => 0,
    'fixed_issues' => 0,
    'scan_date' => 'Never',
    'threat_level' => 'unknown',
    'security_score' => 0
);

if ($scan && is_array($scan)) {
    // Security: Validate scan ID
    $scan_id = intval($scan['id']);
    if ($scan_id > 0) {
        // Count issues by severity with prepared statements
        $high_severity = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d AND severity = %s AND status != %s",
            $scan_id,
            'high',
            'fixed'
        ));

        $medium_severity = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d AND severity = %s AND status != %s",
            $scan_id,
            'medium',
            'fixed'
        ));

        $low_severity = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d AND severity = %s AND status != %s",
            $scan_id,
            'low',
            'fixed'
        ));

        // Security: Sanitize and validate data
        $stats['total_issues'] = max(0, intval($scan['issues_found'] ?? 0));
        $stats['high_severity'] = max(0, intval($high_severity ?? 0));
        $stats['medium_severity'] = max(0, intval($medium_severity ?? 0));
        $stats['low_severity'] = max(0, intval($low_severity ?? 0));
        $stats['fixed_issues'] = max(0, intval($scan['issues_fixed'] ?? 0));
        $stats['scan_date'] = sanitize_text_field($scan['scan_date'] ?? 'Never');

        // Calculate threat level and security score
        $active_issues = $stats['high_severity'] + $stats['medium_severity'] + $stats['low_severity'];
        $stats['threat_level'] = $stats['high_severity'] > 0 ? 'critical' : ($stats['medium_severity'] > 0 ? 'high' : ($stats['low_severity'] > 0 ? 'medium' : 'low'));

        // Security score calculation (0-100, higher is better)
        $total_scanned = max(1, intval($scan['files_scanned'] ?? 1));
        $stats['security_score'] = max(0, min(100, 100 - (($active_issues / $total_scanned) * 100)));
    }
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
switch ($stats['threat_level']) {
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
            <span class="threat-indicator threat-<?php echo esc_attr($stats['threat_level']); ?>">
                <?php echo esc_html(strtoupper($stats['threat_level'])); ?>
            </span>
        </h2>

        <div class="stat-grid">
            <div class="stat-card secure">
                <div class="stat-label"><?php echo esc_html__('Security Score', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($stats['security_score']); ?>%</div>
            </div>

            <div class="stat-card threat-high">
                <div class="stat-label"><?php echo esc_html__('Critical Issues', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($stats['high_severity']); ?></div>
            </div>

            <div class="stat-card threat-medium">
                <div class="stat-label"><?php echo esc_html__('High Issues', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($stats['medium_severity']); ?></div>
            </div>

            <div class="stat-card threat-low">
                <div class="stat-label"><?php echo esc_html__('Medium Issues', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($stats['low_severity']); ?></div>
            </div>

            <div class="stat-card secure">
                <div class="stat-label"><?php echo esc_html__('Issues Resolved', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo esc_html($stats['fixed_issues']); ?></div>
            </div>
        </div>

        <div class="security-summary">
            <?php if ($stats['scan_date'] !== 'Never'): ?>
                <p><strong><?php echo esc_html__('Last Scan:', 'themewire-security'); ?></strong>
                    <?php echo esc_html(wp_date('F j, Y \a\t g:i A', strtotime($stats['scan_date']))); ?></p>
            <?php else: ?>
                <p><strong><?php echo esc_html__('Status:', 'themewire-security'); ?></strong>
                    <?php echo esc_html__('No scans have been performed yet', 'themewire-security'); ?></p>
            <?php endif; ?>

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
            <?php if ($stats['high_severity'] > 0): ?>
                <div class="action-item critical">
                    <div class="action-icon">!</div>
                    <div class="action-content">
                        <h3><?php echo esc_html__('Critical Issues Detected', 'themewire-security'); ?></h3>
                        <p><?php echo sprintf(
                                esc_html__('You have %d critical security issues that require immediate attention.', 'themewire-security'),
                                (int) $stats['high_severity']
                            ); ?></p>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-issues&severity=high')); ?>"
                            class="btn-critical">
                            <?php echo esc_html__('Fix Critical Issues', 'themewire-security'); ?>
                        </a>
                    </div>
                </div>
            <?php elseif ($stats['medium_severity'] > 0): ?>
                <div class="action-item warning">
                    <div class="action-icon">*</div>
                    <div class="action-content">
                        <h3><?php echo esc_html__('High Priority Issues', 'themewire-security'); ?></h3>
                        <p><?php echo sprintf(
                                esc_html__('You have %d high priority issues to address.', 'themewire-security'),
                                (int) $stats['medium_severity']
                            ); ?></p>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=themewire-security-issues&severity=medium')); ?>"
                            class="btn-warning">
                            <?php echo esc_html__('Review Issues', 'themewire-security'); ?>
                        </a>
                    </div>
                </div>
            <?php else: ?>
                <div class="action-item secure">
                    <div class="action-icon">S</div>
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

        <?php
        // Get recent scans with prepared statement
        $recent_scans = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}twss_scans ORDER BY scan_date DESC LIMIT %d",
            5
        ), ARRAY_A);
        ?>

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

                        // Condition 1: No scan is currently in progress
                        if (!$scan_in_progress) {
                            $is_stale_scan = true;
                        }

                        // Condition 2: Different scan ID is running 
                        if ($scan_in_progress && $current_scan_id != $scan_id) {
                            $is_stale_scan = true;
                        }

                        // Condition 3: Scan is older than 10 minutes (more aggressive)
                        $scan_timestamp = strtotime($scan_date);
                        $ten_minutes_ago = time() - 600;
                        if ($scan_timestamp < $ten_minutes_ago) {
                            $is_stale_scan = true;
                        }

                        // Condition 4: Check if scan has progress = 100% but status still running
                        $scan_progress = get_transient("twss_scan_progress_{$scan_id}");
                        if ($scan_progress && isset($scan_progress['percent']) && $scan_progress['percent'] >= 100) {
                            $is_stale_scan = true;
                        }

                        // Fix stale scan
                        if ($is_stale_scan) {
                            // Update stale scan to completed status
                            $wpdb->update(
                                $wpdb->prefix . 'twss_scans',
                                ['status' => 'completed'],
                                ['id' => $scan_id],
                                ['%s'],
                                ['%d']
                            );
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
            <?php if ($stats['scan_date'] === 'Never'): ?>
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