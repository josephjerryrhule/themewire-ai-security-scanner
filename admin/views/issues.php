<?php
/**
 * Admin Issues View.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

// Get the most recent scan
global $wpdb;
$scan = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}twss_scans ORDER BY scan_date DESC LIMIT 1", ARRAY_A);

// Get issues if scan exists
$issues = array();
if ($scan) {
    $issues = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}twss_issues 
         WHERE scan_id = %d AND status IN ('pending', 'confirmed')
         ORDER BY CASE 
            WHEN severity = 'high' THEN 1
            WHEN severity = 'medium' THEN 2
            WHEN severity = 'low' THEN 3
         END, date_detected ASC",
        $scan['id']
    ), ARRAY_A);
}
?>

<div class="wrap themewire-security-wrap">
    <h1><?php _e('Security Issues', 'themewire-security'); ?></h1>
    
    <?php if (empty($scan)): ?>
        <div class="notice notice-warning">
            <p><?php _e('No security scans have been run yet.', 'themewire-security'); ?></p>
        </div>
        <p><a href="<?php echo admin_url('admin.php?page=themewire-security-scan'); ?>" class="button button-primary"><?php _e('Run First Scan', 'themewire-security'); ?></a></p>
    <?php elseif (empty($issues)): ?>
        <div class="notice notice-success">
            <p><?php _e('No security issues were found in your WordPress site.', 'themewire-security'); ?></p>
        </div>
        <p><a href="<?php echo admin_url('admin.php?page=themewire-security-scan'); ?>" class="button button-primary"><?php _e('Run New Scan', 'themewire-security'); ?></a></p>
    <?php else: ?>
        <div class="card">
            <h2 class="card-title"><?php _e('Detected Security Issues', 'themewire-security'); ?></h2>
            <p><?php printf(__('Scan completed on: %s', 'themewire-security'), date('F j, Y, g:i a', strtotime($scan['scan_date']))); ?></p>
            <p><?php printf(__('Found %d issues that need attention.', 'themewire-security'), count($issues)); ?></p>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Severity', 'themewire-security'); ?></th>
                        <th><?php _e('Issue Type', 'themewire-security'); ?></th>
                        <th><?php _e('File Path', 'themewire-security'); ?></th>
                        <th><?php _e('Description', 'themewire-security'); ?></th>
                        <th><?php _e('AI Analysis', 'themewire-security'); ?></th>
                        <th><?php _e('Actions', 'themewire-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($issues as $issue): ?>
                        <tr>
                            <td>
                                <span class="severity-<?php echo esc_attr($issue['severity']); ?>">
                                    <?php echo ucfirst($issue['severity']); ?>
                                </span>
                            </td>
                            <td><?php echo esc_html($issue['issue_type']); ?></td>
                            <td>
                                <div class="file-path" title="<?php echo esc_attr($issue['file_path']); ?>">
                                    <?php echo esc_html(basename($issue['file_path'])); ?>
                                    <span class="path-tooltip"><?php echo esc_html(dirname($issue['file_path'])); ?></span>
                                </div>
                            </td>
                            <td><?php echo esc_html($issue['description']); ?></td>
                            <td>
                                <?php if (!empty($issue['ai_analysis'])): ?>
                                    <button type="button" class="button show-analysis-button" data-analysis="<?php echo esc_attr($issue['ai_analysis']); ?>">
                                        <?php _e('Show Analysis', 'themewire-security'); ?>
                                    </button>
                                <?php else: ?>
                                    <?php _e('No AI analysis available', 'themewire-security'); ?>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div class="action-buttons">
                                    <?php if (!empty($issue['suggested_fix']) && $issue['suggested_fix'] === 'fix'): ?>
                                        <button type="button" class="button fix-issue-button" data-issue-id="<?php echo $issue['id']; ?>">
                                            <?php _e('Fix', 'themewire-security'); ?>
                                        </button>
                                    <?php endif; ?>
                                    
                                    <button type="button" class="button quarantine-button" data-issue-id="<?php echo $issue['id']; ?>">
                                        <?php _e('Quarantine', 'themewire-security'); ?>
                                    </button>
                                    
                                    <button type="button" class="button whitelist-button" data-issue-id="<?php echo $issue['id']; ?>">
                                        <?php _e('Whitelist', 'themewire-security'); ?>
                                    </button>
                                    
                                    <button type="button" class="button delete-button" data-issue-id="<?php echo $issue['id']; ?>">
                                        <?php _e('Delete', 'themewire-security'); ?>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        
        <div id="analysis-modal" class="modal">
            <div class="modal-content">
                <span class="close">&times;</span>
                <h3><?php _e('AI Security Analysis', 'themewire-security'); ?></h3>
                <div id="analysis-content"></div>
            </div>
        </div>
        
        <script>
            // Simple modal for showing AI analysis
            jQuery(document).ready(function($) {
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
                background-color: rgba(0,0,0,0.4);
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