<?php

/**
 * Admin Issues View.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

// Get pagination and filter parameters
$page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
$per_page = 50;
$offset = ($page - 1) * $per_page;

// Get filter parameters
$status_filter = isset($_GET['status_filter']) ? sanitize_text_field($_GET['status_filter']) : '';
$severity_filter = isset($_GET['severity_filter']) ? sanitize_text_field($_GET['severity_filter']) : '';

// Initialize database instance for proper connection handling
try {
    $database = new Themewire_Security_Database();

    // Get issues with pagination and filtering
    $all_issues = $database->get_all_issues($status_filter, $per_page, $offset);
    $issue_counts = $database->get_issue_counts();

    // Get total issues for pagination
    $total_issues = $issue_counts['total'];
    if ($status_filter) {
        $total_issues = $issue_counts[$status_filter] ?? 0;
    }
} catch (Exception $e) {
    echo '<div class="notice notice-error"><p><strong>Error:</strong> ' . esc_html($e->getMessage()) . '</p></div>';
    $all_issues = array();
    $issue_counts = array('pending' => 0, 'resolved' => 0, 'whitelisted' => 0, 'total' => 0);
    $total_issues = 0;
}

// Calculate pagination
$total_pages = ceil($total_issues / $per_page);

// Add this helper function at the top of the file after the PHP opening tag
function is_wordpress_core_file($file_path)
{
    $relative_path = str_replace(ABSPATH, '', $file_path);

    // Core directories
    $core_dirs = array(
        'wp-admin/',
        'wp-includes/',
    );

    // Core files in root
    $core_files = array(
        'index.php',
        'wp-activate.php',
        'wp-blog-header.php',
        'wp-comments-post.php',
        'wp-config-sample.php',
        'wp-cron.php',
        'wp-links-opml.php',
        'wp-load.php',
        'wp-login.php',
        'wp-mail.php',
        'wp-settings.php',
        'wp-signup.php',
        'wp-trackback.php',
        'xmlrpc.php'
    );

    // Check if it's a core file in root
    if (in_array($relative_path, $core_files)) {
        return true;
    }

    // Check if it's in a core directory
    foreach ($core_dirs as $dir) {
        if (strpos($relative_path, $dir) === 0) {
            return true;
        }
    }

    return false;
}
?>

<div class="wrap themewire-security-wrap">
    <div style="margin-bottom: 20px;">
        <h1><?php _e('Security Issues', 'themewire-security'); ?></h1>

        <!-- AI Auto-Fix Mode Toggle -->
        <div class="ai-autofix-toggle" style="margin: 15px 0; padding: 15px; background: linear-gradient(135deg, #FF7342, #ff8c5c); border-radius: 8px; box-shadow: 0 2px 6px rgba(255, 115, 66, 0.3);">
            <div style="display: flex; align-items: center; justify-content: space-between; color: white;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span style="font-size: 24px;">🤖</span>
                    <div>
                        <h3 style="margin: 0; font-size: 16px; font-weight: 600;"><?php _e('AI Auto-Fix Mode', 'themewire-security'); ?></h3>
                        <p style="margin: 0; font-size: 13px; opacity: 0.9;"><?php _e('Automatically fix malware using AI analysis', 'themewire-security'); ?></p>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <label class="toggle-switch" style="position: relative; display: inline-block; width: 60px; height: 34px;">
                        <input type="checkbox" id="global-autofix-toggle" <?php checked(get_option('twss_auto_fix', false)); ?> style="opacity: 0; width: 0; height: 0;">
                        <span class="toggle-slider" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(255,255,255,0.3); transition: .4s; border-radius: 34px; 
                            &:before { content: ''; position: absolute; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }"></span>
                    </label>
                    <span style="font-size: 14px; font-weight: 500;" id="autofix-status">
                        <?php echo get_option('twss_auto_fix', false) ? __('ENABLED', 'themewire-security') : __('DISABLED', 'themewire-security'); ?>
                    </span>
                </div>
            </div>
        </div>

        <?php if (!empty($all_issues)): ?>
            <div>
                <button id="clear-all-issues-button" class="button button-secondary" style="background-color: #dc3232; border-color: #dc3232; color: white; margin-right: 10px;">
                    <?php _e('Clear All Issues', 'themewire-security'); ?>
                </button>
                <?php if ($scan): ?>
                    <button class="clear-scan-issues-button button button-secondary" data-scan-id="<?php echo $scan['id']; ?>" style="background-color: #d63638; border-color: #d63638; color: white;">
                        <?php _e('Clear This Scan', 'themewire-security'); ?>
                    </button>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if (!empty($all_issues)): ?>
        <div class="card">
            <h2 class="card-title"><?php _e('Detected Security Issues', 'themewire-security'); ?></h2>
            <?php if (isset($scan) && $scan && !empty($scan['scan_date'])): ?>
                <p><?php printf(__('Scan completed on: %s', 'themewire-security'), date('F j, Y, g:i a', strtotime($scan['scan_date']))); ?></p>
            <?php endif; ?>

            <!-- Filters Section -->
            <div class="filters-section" style="margin: 20px 0; padding: 15px; background: #FBF6F0; border: 1px solid #FF7342; border-radius: 6px;">
                <form method="get" id="issues-filter-form">
                    <input type="hidden" name="page" value="<?php echo esc_attr($_GET['page']); ?>">
                    <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                        <div>
                            <label for="status_filter" style="font-weight: 600; margin-right: 5px;">
                                <?php _e('Status:', 'themewire-security'); ?>
                            </label>
                            <select name="status_filter" id="status_filter" style="padding: 5px; border: 1px solid #FF7342; border-radius: 4px;">
                                <option value=""><?php _e('All Statuses', 'themewire-security'); ?></option>
                                <option value="pending" <?php selected($status_filter, 'pending'); ?>><?php _e('Pending', 'themewire-security'); ?></option>
                                <option value="confirmed" <?php selected($status_filter, 'confirmed'); ?>><?php _e('Confirmed', 'themewire-security'); ?></option>
                                <option value="resolved" <?php selected($status_filter, 'resolved'); ?>><?php _e('Resolved', 'themewire-security'); ?></option>
                                <option value="whitelisted" <?php selected($status_filter, 'whitelisted'); ?>><?php _e('Whitelisted', 'themewire-security'); ?></option>
                            </select>
                        </div>
                        <div>
                            <label for="severity_filter" style="font-weight: 600; margin-right: 5px;">
                                <?php _e('Severity:', 'themewire-security'); ?>
                            </label>
                            <select name="severity_filter" id="severity_filter" style="padding: 5px; border: 1px solid #FF7342; border-radius: 4px;">
                                <option value=""><?php _e('All Severities', 'themewire-security'); ?></option>
                                <option value="high" <?php selected($severity_filter, 'high'); ?>><?php _e('High', 'themewire-security'); ?></option>
                                <option value="medium" <?php selected($severity_filter, 'medium'); ?>><?php _e('Medium', 'themewire-security'); ?></option>
                                <option value="low" <?php selected($severity_filter, 'low'); ?>><?php _e('Low', 'themewire-security'); ?></option>
                            </select>
                        </div>
                        <div>
                            <button type="submit" class="button" style="background: #FF7342; color: white; border: none; padding: 6px 12px; border-radius: 4px;">
                                <?php _e('Filter', 'themewire-security'); ?>
                            </button>
                            <a href="<?php echo admin_url('admin.php?page=' . $_GET['page']); ?>" class="button" style="margin-left: 5px; background: #FF7342; color: white; border: none; padding: 6px 12px; border-radius: 4px;">
                                <?php _e('Clear', 'themewire-security'); ?>
                            </a>
                        </div>
                        <div style="margin-left: auto; color: #000000; opacity: 0.7;">
                            <?php printf(
                                __('Showing %d-%d of %d total issues', 'themewire-security'),
                                $offset + 1,
                                min($offset + $per_page, $total_issues),
                                $total_issues
                            ); ?>
                        </div>
                    </div>
                </form>
            </div>

            <?php if (empty($all_issues)): ?>
                <div class="notice notice-info" style="margin: 20px 0;">
                    <p><?php _e('No issues match the current filters.', 'themewire-security'); ?></p>
                </div>
            <?php else: ?>

                <!-- Bulk Actions Bar -->
                <div class="bulk-actions-bar" style="margin: 15px 0; padding: 10px; background: #FBF6F0; border: 1px solid #FF7342; border-radius: 6px;">
                    <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                        <label style="font-weight: 600;">
                            <input type="checkbox" id="select-all-files" style="margin-right: 5px;">
                            <?php _e('Select All', 'themewire-security'); ?>
                        </label>
                        <span style="color: #000000; opacity: 0.7;">|</span>
                        <button type="button" id="bulk-fix-selected" class="button" disabled style="background: #FF7342; color: white; border: none; border-radius: 3px;">
                            <?php _e('Fix', 'themewire-security'); ?>
                        </button>
                        <button type="button" id="bulk-quarantine-selected" class="button" disabled style="background: #FF7342; color: white; border: none; border-radius: 3px;">
                            <?php _e('Quarantine', 'themewire-security'); ?>
                        </button>
                        <button type="button" id="bulk-delete-selected" class="button" disabled style="background: #FF7342; color: white; border: none; border-radius: 3px;">
                            <?php _e('Delete', 'themewire-security'); ?>
                        </button>
                        <button type="button" id="bulk-whitelist-selected" class="button" disabled style="background: #FF7342; color: white; border: none; border-radius: 3px;">
                            <?php _e('Whitelist', 'themewire-security'); ?>
                        </button>
                    </div>
                </div>

                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 40px;">
                                <input type="checkbox" id="select-all-files-header">
                            </th>
                            <th><?php _e('Status', 'themewire-security'); ?></th>
                            <th><?php _e('File Path', 'themewire-security'); ?></th>
                            <th><?php _e('AI Verdict', 'themewire-security'); ?></th>
                            <th><?php _e('Actions', 'themewire-security'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($all_issues as $issue): ?>
                            <tr>
                                <td>
                                    <input type="checkbox" class="file-checkbox" value="<?php echo esc_attr($issue['id']); ?>">
                                </td>
                                <td>
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <span class="status-badge severity-<?php echo esc_attr($issue['severity']); ?>" style="padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;">
                                            <?php
                                            switch ($issue['severity']) {
                                                case 'high':
                                                    echo '🔴 ' . __('Infected', 'themewire-security');
                                                    break;
                                                case 'medium':
                                                    echo '🟡 ' . __('Suspicious', 'themewire-security');
                                                    break;
                                                case 'low':
                                                    echo '🟠 ' . __('Unknown', 'themewire-security');
                                                    break;
                                                default:
                                                    echo '⚪ ' . __('Clean', 'themewire-security');
                                            }
                                            ?>
                                        </span>
                                        <small style="color: #000000; opacity: 0.7;">
                                            <?php echo esc_html($issue['issue_type']); ?>
                                        </small>
                                    </div>
                                </td>
                                <td>
                                    <div class="file-path-container">
                                        <strong style="color: #000000;"><?php echo esc_html(basename($issue['file_path'])); ?></strong>
                                        <br>
                                        <small style="color: #000000; opacity: 0.6; font-family: monospace; font-size: 11px;">
                                            <?php echo esc_html(dirname($issue['file_path'])); ?>
                                        </small>
                                    </div>
                                </td>
                                <td>
                                    <div class="ai-verdict-container">
                                        <?php if (!empty($issue['ai_analysis'])): ?>
                                            <?php
                                            $ai_data = json_decode($issue['ai_analysis'], true);
                                            if ($ai_data && isset($ai_data['explanation'])) {
                                                $explanation = $ai_data['explanation'];
                                                $is_malware = isset($ai_data['is_malware']) ? $ai_data['is_malware'] : false;
                                                $suggested_fix = isset($ai_data['suggested_fix']) ? $ai_data['suggested_fix'] : '';
                                            } else {
                                                $explanation = $issue['ai_analysis'];
                                                $is_malware = false;
                                                $suggested_fix = '';
                                            }
                                            ?>
                                            <div class="ai-verdict" style="max-width: 300px;">
                                                <div style="margin-bottom: 5px;">
                                                    <span style="font-weight: 600; color: <?php echo $is_malware ? '#d63638' : '#46b450'; ?>;">
                                                        <?php echo $is_malware ? 'MALICIOUS' : 'SAFE'; ?>
                                                    </span>
                                                </div>
                                                <div style="font-size: 12px; color: #000000; opacity: 0.8; line-height: 1.4;">
                                                    <?php echo esc_html(substr($explanation, 0, 100)); ?>
                                                    <?php if (strlen($explanation) > 100): ?>
                                                        <span>...</span>
                                                        <a href="#" class="show-full-analysis" data-full-text="<?php echo esc_attr($explanation); ?>" style="color: #FF7342;">
                                                            <?php _e('Show More', 'themewire-security'); ?>
                                                        </a>
                                                    <?php endif; ?>
                                                </div>
                                                <?php if ($suggested_fix): ?>
                                                    <div style="margin-top: 5px;">
                                                        <small style="color: #FF7342; font-weight: 600;">
                                                            <?php _e('Suggested:', 'themewire-security'); ?> <?php echo esc_html(ucfirst($suggested_fix)); ?>
                                                        </small>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                        <?php else: ?>
                                            <div style="display: flex; align-items: center; gap: 8px;">
                                                <span style="color: #000000; opacity: 0.5; font-style: italic;">
                                                    <?php _e('No AI analysis available', 'themewire-security'); ?>
                                                </span>
                                                <button type="button" class="button ai-analyze-button" data-issue-id="<?php echo $issue['id']; ?>" style="font-size: 11px; padding: 2px 8px; background: #FF7342; color: white; border: none; border-radius: 3px;">
                                                    <?php _e('Analyze', 'themewire-security'); ?>
                                                </button>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td>
                                    <div class="action-buttons" style="display: flex; gap: 5px; flex-wrap: wrap;">
                                        <?php
                                        // Check if it's a WordPress core file
                                        $is_core_file = is_wordpress_core_file($issue['file_path']);
                                        ?>

                                        <?php if ($is_core_file && ($issue['issue_type'] === 'core_file_missing' || $issue['issue_type'] === 'core_file_modified')): ?>
                                            <button type="button" class="button restore-core-button" data-issue-id="<?php echo $issue['id']; ?>" style="font-size: 11px; padding: 2px 8px; background: #FF7342; color: white; border: none; border-radius: 3px;">
                                                <?php _e('Restore', 'themewire-security'); ?>
                                            </button>
                                        <?php endif; ?>

                                        <?php if (!empty($issue['suggested_fix']) && in_array($issue['suggested_fix'], ['fix', 'quarantine', 'delete']) && !$is_core_file): ?>
                                            <button type="button" class="button fix-issue-button" data-issue-id="<?php echo $issue['id']; ?>" style="font-size: 11px; padding: 2px 8px; background: #FF7342; color: white; border: none; border-radius: 3px;">
                                                <?php _e('Fix', 'themewire-security'); ?>
                                            </button>
                                        <?php endif; ?>

                                        <button type="button" class="button quarantine-button" data-issue-id="<?php echo $issue['id']; ?>" style="font-size: 11px; padding: 2px 8px; background: #FF7342; color: white; border: none; border-radius: 3px;">
                                            <?php _e('Quarantine', 'themewire-security'); ?>
                                        </button>

                                        <button type="button" class="button whitelist-button" data-issue-id="<?php echo $issue['id']; ?>" style="font-size: 11px; padding: 2px 8px; background: #FF7342; color: white; border: none; border-radius: 3px;">
                                            <?php _e('Whitelist', 'themewire-security'); ?>
                                        </button>

                                        <?php if (!$is_core_file): ?>
                                            <button type="button" class="button delete-button" data-issue-id="<?php echo $issue['id']; ?>" style="font-size: 11px; padding: 2px 8px; background: #FF7342; color: white; border: none; border-radius: 3px;">
                                                <?php _e('Delete', 'themewire-security'); ?>
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- Pagination Controls -->
                <?php if ($total_pages > 1): ?>
                    <div class="pagination-wrapper" style="margin: 20px 0; padding: 15px; background: #FBF6F0; border: 1px solid #FF7342; border-radius: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                            <div style="color: #000000; opacity: 0.8;">
                                <?php printf(__('Page %d of %d', 'themewire-security'), $page, $total_pages); ?>
                            </div>
                            <div class="pagination-links" style="display: flex; gap: 5px; align-items: center;">
                                <?php
                                $base_url = admin_url('admin.php?page=' . $_GET['page']);
                                if (!empty($status_filter)) {
                                    $base_url .= '&status_filter=' . urlencode($status_filter);
                                }
                                if (!empty($severity_filter)) {
                                    $base_url .= '&severity_filter=' . urlencode($severity_filter);
                                }
                                ?>

                                <?php if ($page > 1): ?>
                                    <a href="<?php echo $base_url . '&paged=1'; ?>" class="button" style="font-size: 12px; padding: 4px 8px;">
                                        « <?php _e('First', 'themewire-security'); ?>
                                    </a>
                                    <a href="<?php echo $base_url . '&paged=' . ($page - 1); ?>" class="button" style="font-size: 12px; padding: 4px 8px;">
                                        ‹ <?php _e('Previous', 'themewire-security'); ?>
                                    </a>
                                <?php endif; ?>

                                <?php
                                // Show page numbers
                                $start_page = max(1, $page - 2);
                                $end_page = min($total_pages, $page + 2);

                                for ($i = $start_page; $i <= $end_page; $i++):
                                ?>
                                    <?php if ($i == $page): ?>
                                        <span class="button button-primary" style="font-size: 12px; padding: 4px 8px; background: #FF7342; border-color: #FF7342;">
                                            <?php echo $i; ?>
                                        </span>
                                    <?php else: ?>
                                        <a href="<?php echo $base_url . '&paged=' . $i; ?>" class="button" style="font-size: 12px; padding: 4px 8px;">
                                            <?php echo $i; ?>
                                        </a>
                                    <?php endif; ?>
                                <?php endfor; ?>

                                <?php if ($page < $total_pages): ?>
                                    <a href="<?php echo $base_url . '&paged=' . ($page + 1); ?>" class="button" style="font-size: 12px; padding: 4px 8px;">
                                        <?php _e('Next', 'themewire-security'); ?> ›
                                    </a>
                                    <a href="<?php echo $base_url . '&paged=' . $total_pages; ?>" class="button" style="font-size: 12px; padding: 4px 8px;">
                                        <?php _e('Last', 'themewire-security'); ?> »
                                    </a>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

        </div>
    <?php endif; ?>

    <?php if (empty($all_issues)): ?>
        <?php if (empty($scan)): ?>
            <div class="notice notice-warning">
                <p><?php _e('No security scans have been run yet.', 'themewire-security'); ?></p>
            </div>
            <p><a href="<?php echo admin_url('admin.php?page=themewire-security-scan'); ?>" class="button button-primary"><?php _e('Run First Scan', 'themewire-security'); ?></a></p>
        <?php else: ?>
            <div class="notice notice-success">
                <p><?php _e('No security issues were found in your WordPress site.', 'themewire-security'); ?></p>
            </div>
            <p><a href="<?php echo admin_url('admin.php?page=themewire-security-scan'); ?>" class="button button-primary"><?php _e('Run New Scan', 'themewire-security'); ?></a></p>
        <?php endif; ?>
    <?php endif; ?>

    <div id="analysis-modal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h3><?php _e('AI Security Analysis', 'themewire-security'); ?></h3>
            <div id="analysis-content"></div>
        </div>
    </div>

    <script>
        // Modal for showing AI analysis
        jQuery(document).ready(function($) {
            console.log('Issues page JavaScript loaded');
            console.log('Available action buttons:', $('.action-buttons button').length);

            var modal = $('#analysis-modal');
            var analysisContent = $('#analysis-content');

            $('.show-analysis-button').on('click', function() {
                var analysis = $(this).data('analysis');
                analysisContent.text(analysis);
                modal.show();
            });

            $('.close').on('click', function() {
                modal.hide();
            });

            $(window).on('click', function(event) {
                if ($(event.target).is(modal)) {
                    modal.hide();
                }
            });
        });
    </script>

    <style>
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.4);
        }

        .modal-content {
            background-color: #fff;
            margin: 10% auto;
            padding: 20px;
            border-radius: 5px;
            max-width: 600px;
            max-height: 70vh;
            overflow-y: auto;
        }

        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }

        .path-tooltip {
            font-size: 0.8em;
            color: #666;
            display: block;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 200px;
        }
    </style>
<?php endif; ?>
</div>