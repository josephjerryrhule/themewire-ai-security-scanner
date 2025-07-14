<?php

/**
 * Admin Dashboard View.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

// Get the most recent scan
global $wpdb;
$scan = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}twss_scans ORDER BY scan_date DESC LIMIT 1", ARRAY_A);

// Get scan stats if available
$stats = array(
    'total_issues' => 0,
    'high_severity' => 0,
    'medium_severity' => 0,
    'low_severity' => 0,
    'fixed_issues' => 0,
    'scan_date' => 'Never'
);

if ($scan) {
    // Count issues by severity
    $high_severity = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d AND severity = 'high'",
        $scan['id']
    ));

    $medium_severity = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d AND severity = 'medium'",
        $scan['id']
    ));

    $low_severity = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->prefix}twss_issues WHERE scan_id = %d AND severity = 'low'",
        $scan['id']
    ));

    $stats['total_issues'] = $scan['issues_found'];
    $stats['high_severity'] = $high_severity;
    $stats['medium_severity'] = $medium_severity;
    $stats['low_severity'] = $low_severity;
    $stats['fixed_issues'] = $scan['issues_fixed'];
    $stats['scan_date'] = $scan['scan_date'];
}

// Get the next scheduled scan time
$scheduler = new Themewire_Security_Scheduler();
$next_scan = $scheduler->get_next_scan_time();
?>

<div class="wrap themewire-security-wrap">
    <div class="header-actions">
        <h1><?php _e('Security AI Dashboard', 'themewire-security'); ?></h1>
        <a href="<?php echo admin_url('admin.php?page=themewire-security-scan'); ?>" class="button button-primary"><?php _e('Run New Scan', 'themewire-security'); ?></a>
    </div>

    <div class="card">
        <h2 class="card-title"><?php _e('Security Status', 'themewire-security'); ?></h2>

        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-label"><?php _e('Total Issues', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo $stats['total_issues']; ?></div>
            </div>

            <div class="stat-card high-severity">
                <div class="stat-label"><?php _e('High Severity', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo $stats['high_severity']; ?></div>
            </div>

            <div class="stat-card medium-severity">
                <div class="stat-label"><?php _e('Medium Severity', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo $stats['medium_severity']; ?></div>
            </div>

            <div class="stat-card low-severity">
                <div class="stat-label"><?php _e('Low Severity', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo $stats['low_severity']; ?></div>
            </div>

            <div class="stat-card">
                <div class="stat-label"><?php _e('Issues Fixed', 'themewire-security'); ?></div>
                <div class="stat-number"><?php echo $stats['fixed_issues']; ?></div>
            </div>
        </div>

        <p><?php printf(__('Last scan completed on: <strong>%s</strong>', 'themewire-security'), $stats['scan_date'] !== 'Never' ? date('F j, Y, g:i a', strtotime($stats['scan_date'])) : 'Never'); ?></p>
        <?php if ($next_scan): ?>
            <p><?php printf(__('Next scheduled scan: <strong>%s</strong>', 'themewire-security'), date('F j, Y, g:i a', strtotime($next_scan))); ?></p>
        <?php endif; ?>
    </div>

    <?php if ($stats['total_issues'] > 0): ?>
        <div class="card">
            <h2 class="card-title"><?php _e('Security Issues', 'themewire-security'); ?></h2>

            <?php if ($stats['high_severity'] > 0): ?>
                <div class="notice notice-error">
                    <p><?php printf(__('<strong>%d high severity</strong> issues found that require immediate attention!', 'themewire-security'), $stats['high_severity']); ?></p>
                </div>
            <?php endif; ?>

            <?php if ($stats['medium_severity'] > 0): ?>
                <div class="notice notice-warning">
                    <p><?php printf(__('<strong>%d medium severity</strong> issues found that should be addressed.', 'themewire-security'), $stats['medium_severity']); ?></p>
                </div>
            <?php endif; ?>

            <p><a href="<?php echo admin_url('admin.php?page=themewire-security-issues'); ?>" class="button"><?php _e('View & Fix Issues', 'themewire-security'); ?></a></p>
        </div>
    <?php else: ?>
        <?php if ($stats['scan_date'] !== 'Never'): ?>
            <div class="card">
                <h2 class="card-title"><?php _e('Your Site is Secure', 'themewire-security'); ?></h2>
                <div class="notice notice-success">
                    <p><?php _e('No security issues have been found on your site.', 'themewire-security'); ?></p>
                </div>
            </div>
        <?php else: ?>
            <div class="card">
                <h2 class="card-title"><?php _e('Get Started', 'themewire-security'); ?></h2>
                <p><?php _e('No security scans have been run yet. Run your first scan to check your site for security issues.', 'themewire-security'); ?></p>
                <p><a href="<?php echo admin_url('admin.php?page=themewire-security-scan'); ?>" class="button button-primary"><?php _e('Run First Scan', 'themewire-security'); ?></a></p>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <div class="card">
        <h2 class="card-title"><?php _e('About Themewire AI Security', 'themewire-security'); ?></h2>
        <p><?php _e('Themewire AI Security Scanner uses artificial intelligence to detect and fix security vulnerabilities, malware, and hacked files in your WordPress site.', 'themewire-security'); ?></p>
        <p><?php _e('Key features:', 'themewire-security'); ?></p>
        <ul>
            <li><?php _e('AI-powered malware detection', 'themewire-security'); ?></li>
            <li><?php _e('WordPress core file integrity checks', 'themewire-security'); ?></li>
            <li><?php _e('Plugin and theme security scanning', 'themewire-security'); ?></li>
            <li><?php _e('Automatic fixing of security issues', 'themewire-security'); ?></li>
            <li><?php _e('Quarantine system for malicious files', 'themewire-security'); ?></li>
            <li><?php _e('Daily scheduled scans', 'themewire-security'); ?></li>
        </ul>
        <p class="plugin-meta">
            <small><?php printf(
                        __('Version %s | Last Updated: %s | By %s', 'themewire-security'),
                        TWSS_VERSION,
                        '2025-07-14 23:02:42',
                        'josephjerryrhule'
                    );
                    ?></small>
        </p>
    </div>
</div>