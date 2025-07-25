<?php

/**
 * Admin Scan View.
 *
 * @link       https://themewire.co
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

// Get scan in progress status
$scan_in_progress = get_transient('twss_scan_in_progress') === 'yes';

// Get the most recent scan
global $wpdb;
$scan = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}twss_scans ORDER BY scan_date DESC LIMIT 1", ARRAY_A);
?>

<div class="wrap themewire-security-wrap">
    <h1><?php _e('Security Scan', 'themewire-security'); ?></h1>

    <div class="card">
        <h2 class="card-title"><?php _e('Scan Your Site', 'themewire-security'); ?></h2>
        <p><?php _e('Run a comprehensive security scan of your WordPress site to detect malware, vulnerabilities, and other security issues.', 'themewire-security'); ?></p>

        <p><?php _e('The scan will check:', 'themewire-security'); ?></p>
        <ul>
            <li><?php _e('WordPress core files for modifications', 'themewire-security'); ?></li>
            <li><?php _e('Plugin files for malicious code', 'themewire-security'); ?></li>
            <li><?php _e('Theme files for vulnerabilities', 'themewire-security'); ?></li>
            <li><?php _e('Uploads directory for suspicious files', 'themewire-security'); ?></li>
        </ul>

        <p><?php _e('This scan may take several minutes depending on the size of your site.', 'themewire-security'); ?></p>

        <?php
        // Check for incomplete scan more thoroughly
        $current_scan_id = get_option('twss_current_scan_id');
        $has_incomplete_scan = false;

        if ($current_scan_id) {
            // Check if the scan actually exists and is not completed
            $scan_status = $wpdb->get_var($wpdb->prepare("SELECT status FROM {$wpdb->prefix}twss_scans WHERE id = %d", $current_scan_id));
            $has_incomplete_scan = ($scan_status && !in_array($scan_status, array('completed', 'failed')));

            // Clean up if scan is actually completed but option wasn't cleared
            if (!$has_incomplete_scan) {
                delete_option('twss_current_scan_id');
                $current_scan_id = null;
            }
        }

        // Additional cleanup: If scan is marked as in progress but there's no current scan ID or it's completed
        $scan_in_progress_transient = get_transient('twss_scan_in_progress');
        if ($scan_in_progress_transient === 'yes' && (!$current_scan_id || !$has_incomplete_scan)) {
            // Clear stale scan progress flag
            delete_transient('twss_scan_in_progress');
            delete_transient('twss_scan_last_activity');
            delete_transient('twss_optimized_scan_state');
            delete_transient('twss_chunked_scan_state');
            $scan_in_progress = false; // Update the variable for this page load
        }

        // Additional validation: Check if scan_in_progress is true but scan ID has a completed status
        if ($scan_in_progress && $current_scan_id) {
            $scan_status = $wpdb->get_var($wpdb->prepare("SELECT status FROM {$wpdb->prefix}twss_scans WHERE id = %d", $current_scan_id));
            if ($scan_status && in_array($scan_status, array('completed', 'failed', 'stopped'))) {
                // Scan is actually completed but transient wasn't cleared - fix this
                delete_transient('twss_scan_in_progress');
                delete_transient('twss_scan_last_activity');
                delete_transient('twss_optimized_scan_state');
                delete_transient('twss_chunked_scan_state');
                delete_option('twss_current_scan_id');
                $scan_in_progress = false;
                $has_incomplete_scan = false;
                $current_scan_id = null;
            }
        }
        ?>
        <?php if ($has_incomplete_scan): ?>
            <div class="notice notice-warning">
                <p><?php _e('A previous scan was interrupted. You can resume it or start a new scan.', 'themewire-security'); ?></p>
            </div>
            <button id="resume-scan-button" class="button button-primary" <?php echo $scan_in_progress ? 'disabled' : ''; ?>>
                <?php _e('Resume Scan', 'themewire-security'); ?>
            </button>
        <?php endif; ?>

        <button id="start-scan-button" class="button button-primary" <?php echo $scan_in_progress ? 'disabled' : ''; ?>>
            <?php echo $scan_in_progress ? __('Scan in progress...', 'themewire-security') : __('Start New Scan', 'themewire-security'); ?>
        </button>

        <?php if ($scan_in_progress): ?>
            <button id="stop-scan-button" class="button button-secondary" style="margin-left: 10px;">
                <?php _e('Stop Scan', 'themewire-security'); ?>
            </button>
        <?php endif; ?>

        <button id="clear-all-issues-button" class="button button-secondary" style="margin-left: 10px; background-color: #dc3232; border-color: #dc3232; color: white;">
            <?php _e('Clear All Issues', 'themewire-security'); ?>
        </button>

        <button id="cleanup-ghost-files-button" class="button button-secondary" style="margin-left: 10px; background-color: #f56e28; border-color: #f56e28; color: white;">
            <?php _e('Clean Ghost Files', 'themewire-security'); ?>
        </button>
    </div>

    <div id="scan-progress-container" style="display: none;" class="card">
        <h2 class="card-title"><?php _e('Scan Progress', 'themewire-security'); ?></h2>

        <div class="scan-progress-wrapper">
            <div class="scan-progress-bar">
                <div class="scan-progress-bar-fill" style="width: 0%;"></div>
            </div>
            <div class="scan-progress-text">0%</div>
        </div>

        <div id="scan-stage-info" class="scan-stage-info">
            <p><?php _e('Preparing scan...', 'themewire-security'); ?></p>
        </div>
    </div>

    <div id="scan-status-area">
        <?php if ($scan_in_progress): ?>
            <div class="scan-status"><?php _e('Scan in progress...', 'themewire-security'); ?> <span class="loading-spinner"></span></div>
        <?php endif; ?>
    </div>

    <div id="scan-results-area">
        <?php if ($scan && !$scan_in_progress): ?>
            <div class="card">
                <h2 class="card-title"><?php _e('Last Scan Results', 'themewire-security'); ?></h2>
                <p><?php printf(__('Scan completed on: %s', 'themewire-security'), date('F j, Y, g:i a', strtotime($scan['scan_date']))); ?></p>

                <div class="stat-grid">
                    <div class="stat-card">
                        <div class="stat-label"><?php _e('Total Issues', 'themewire-security'); ?></div>
                        <div class="stat-number"><?php echo $scan['issues_found']; ?></div>
                    </div>

                    <div class="stat-card">
                        <div class="stat-label"><?php _e('Issues Fixed', 'themewire-security'); ?></div>
                        <div class="stat-number"><?php echo $scan['issues_fixed']; ?></div>
                    </div>
                </div>

                <?php if ($scan['issues_found'] > 0): ?>
                    <p><a href="<?php echo admin_url('admin.php?page=themewire-security-issues'); ?>" class="button"><?php _e('View Issues', 'themewire-security'); ?></a></p>
                <?php else: ?>
                    <div class="notice notice-success">
                        <p><?php _e('No security issues were found in your WordPress site.', 'themewire-security'); ?></p>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>