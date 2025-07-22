/**
 * Admin JavaScript for Themewire AI Security Scanner
 *
 * @link       https://themewire.com
 * @since      1.0.0
 * @last-modified 2025-07-14 23:35:07
 * @modified-by josephjerryrhuleit
 *
 * @package    Themewire_Security
 */

(function ($) {
  "use strict";

  // Global variables for tracking scan progress
  var overallProgress = 0;
  var currentStage = "";
  var stages = ["core", "plugins", "themes", "uploads", "ai_analysis"];
  var stageWeights = {
    core: 0.3, // 30% of total progress
    plugins: 0.3, // 30% of total progress
    themes: 0.2, // 20% of total progress
    uploads: 0.1, // 10% of total progress
    ai_analysis: 0.1, // 10% of total progress
  };
  var stageProgress = {
    core: 0,
    plugins: 0,
    themes: 0,
    uploads: 0,
    ai_analysis: 0,
  };
  var pollInterval = null;

  // Make pollInterval globally accessible for stop scan functionality
  window.twssPollInterval = pollInterval;

  // Document ready
  $(function () {
    console.log("Themewire Security Admin JS loaded");
    console.log("TWSS Data:", twss_data);
    console.log("Current URL:", window.location.href);

    // Always set up action buttons if we're on any themewire-security page
    if (window.location.href.indexOf("themewire-security") !== -1) {
      console.log(
        "Themewire Security page detected, setting up action button handlers"
      );
      // Set up immediately and also after a short delay for dynamically loaded content
      setupActionButtons();
      setTimeout(setupActionButtons, 1000);
    }

    // Handle Start Scan button click
    $("#start-scan-button").on("click", function () {
      console.log("Start scan button clicked");
      startScan();
    });

    // Handle Resume Scan button click
    $("#resume-scan-button").on("click", function () {
      console.log("Resume scan button clicked");
      resumeScan();
    });

    // Handle Stop Scan button click (uses global function from additional.js)
    $("#stop-scan-button").on("click", function () {
      console.log("Stop scan button clicked");
      if (typeof window.stopScan === "function") {
        window.stopScan();
      }
    });

    // Handle Clear All Issues button click (uses global function from additional.js)
    $("#clear-all-issues-button").on("click", function () {
      console.log("Clear all issues button clicked");
      if (typeof window.clearAllIssues === "function") {
        window.clearAllIssues();
      }
    });

    // Handle Clean Ghost Files button click
    $("#cleanup-ghost-files-button").on("click", function () {
      console.log("Clean ghost files button clicked");
      cleanupGhostFiles();
    });

    // Handle Clear Scan Issues button click (uses global function from additional.js)
    $(document).on("click", ".clear-scan-issues-button", function () {
      var scanId = $(this).data("scan-id");
      console.log("Clear scan issues button clicked for scan:", scanId);
      if (typeof window.clearScanIssues === "function") {
        window.clearScanIssues(scanId);
      }
    });

    // AI Connection Testing
    setupAIConnectionTesting();

    // Bulk Actions for Scan Results
    setupBulkActions();

    // Enhanced Filtering for Issues Page
    setupIssuesFiltering();
  });

  /**
   * Perform an action on a specific issue
   *
   * @param {jQuery} button - The button that was clicked
   * @param {string} action - The AJAX action to perform
   * @param {number} issueId - The issue ID to act on
   * @param {string} loadingText - Text to show while processing
   * @param {string} originalText - Original button text to restore
   * @param {object} extraData - Additional data to send with the request
   */
  function performIssueAction(
    button,
    action,
    issueId,
    loadingText,
    originalText,
    extraData
  ) {
    if (!issueId) {
      alert("Invalid issue ID");
      return;
    }

    // Disable button and show loading state
    button.prop("disabled", true);
    var buttonOriginalText = originalText || button.text();
    button.text(loadingText || "Processing...");

    // Prepare AJAX data
    var ajaxData = {
      action: action,
      issue_id: issueId,
      nonce: twss_data.nonce,
    };

    // Add any extra data
    if (extraData && typeof extraData === "object") {
      $.extend(ajaxData, extraData);
    }

    // Perform action via AJAX
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: ajaxData,
      success: function (response) {
        if (response.success) {
          // Show success message
          alert(response.data.message || "Action completed successfully!");

          // Remove the issue row from the table if action was successful
          var issueRow = button.closest("tr");
          if (issueRow.length) {
            issueRow.fadeOut(300, function () {
              $(this).remove();
            });
          } else {
            // Reload the page to show updated state if no specific row to remove
            location.reload();
          }
        } else {
          alert("Error: " + (response.data.message || "Action failed"));
        }
      },
      error: function (xhr, status, error) {
        console.error("AJAX Error:", status, error);
        alert("Error performing action. Please try again.");
      },
      complete: function () {
        // Re-enable button and restore original text
        button.prop("disabled", false);
        button.text(buttonOriginalText);
      },
    });
  }

  /**
   * Setup action button event handlers
   */
  function setupActionButtons() {
    console.log("Setting up action button handlers");

    // Check if buttons exist
    var buttons = $(
      ".fix-issue-button, .quarantine-button, .whitelist-button, .delete-button, .restore-core-button, .ai-analyze-button"
    );
    console.log("Found", buttons.length, "action buttons on page");

    // If no buttons found, log available elements for debugging
    if (buttons.length === 0) {
      console.log(
        "No action buttons found. Available elements with data-issue-id:",
        $("[data-issue-id]")
      );
      console.log("All buttons on page:", $("button"));
    }

    // Use event delegation on document to catch all button clicks
    $(document)
      .off("click.twss-actions")
      .on("click.twss-actions", ".fix-issue-button", function (e) {
        e.preventDefault();
        e.stopPropagation();
        console.log("Auto fix button clicked via delegation");
        const button = $(this);
        const issueId = button.data("issue-id");
        console.log("Issue ID:", issueId);

        if (
          confirm(
            "Are you sure you want to automatically fix this issue? This will apply the suggested fix."
          )
        ) {
          performIssueAction(
            button,
            "twss_fix_issue",
            issueId,
            "Fixing...",
            "Auto Fix"
          );
        }
      });

    $(document)
      .off("click.twss-quarantine")
      .on("click.twss-quarantine", ".quarantine-button", function (e) {
        e.preventDefault();
        e.stopPropagation();
        console.log("Quarantine button clicked via delegation");
        const button = $(this);
        const issueId = button.data("issue-id");
        console.log("Issue ID:", issueId);

        if (
          confirm(
            "Are you sure you want to quarantine this file? The file will be moved to a secure location and made inaccessible."
          )
        ) {
          performIssueAction(
            button,
            "twss_quarantine_file",
            issueId,
            "Quarantining...",
            "Quarantine"
          );
        }
      });

    $(document)
      .off("click.twss-whitelist")
      .on("click.twss-whitelist", ".whitelist-button", function (e) {
        e.preventDefault();
        e.stopPropagation();
        console.log("Whitelist button clicked via delegation");
        const button = $(this);
        const issueId = button.data("issue-id");
        console.log("Issue ID:", issueId);

        const reason = prompt(
          "Please provide a reason for whitelisting this file:"
        );

        if (reason !== null && reason.trim() !== "") {
          performIssueAction(
            button,
            "twss_whitelist_file",
            issueId,
            "Whitelisting...",
            "Whitelist",
            { reason: reason }
          );
        }
      });

    $(document)
      .off("click.twss-delete")
      .on("click.twss-delete", ".delete-button", function (e) {
        e.preventDefault();
        e.stopPropagation();
        console.log("Delete button clicked via delegation");
        const button = $(this);
        const issueId = button.data("issue-id");
        console.log("Issue ID:", issueId);

        if (
          confirm(
            "Are you sure you want to delete this file? This action cannot be undone. The file will be backed up to quarantine before deletion."
          )
        ) {
          performIssueAction(
            button,
            "twss_delete_file",
            issueId,
            "Deleting...",
            "Delete"
          );
        }
      });

    $(document)
      .off("click.twss-restore")
      .on("click.twss-restore", ".restore-core-button", function (e) {
        e.preventDefault();
        e.stopPropagation();
        console.log("Restore core file button clicked via delegation");
        const button = $(this);
        const issueId = button.data("issue-id");
        console.log("Issue ID:", issueId);

        if (
          confirm(
            "Are you sure you want to restore this WordPress core file? This will download the original file from WordPress.org."
          )
        ) {
          performIssueAction(
            button,
            "twss_restore_core_file",
            issueId,
            "Restoring...",
            "Restore Core File"
          );
        }
      });

    $(document)
      .off("click.twss-ai-analyze")
      .on("click.twss-ai-analyze", ".ai-analyze-button", function (e) {
        e.preventDefault();
        e.stopPropagation();
        console.log("AI analyze button clicked via delegation");
        const button = $(this);
        const issueId = button.data("issue-id");
        console.log("Issue ID:", issueId);

        // Confirm with user before running AI analysis
        if (
          confirm(
            "Run AI analysis on this file? This will send the file content to the configured AI service for security analysis."
          )
        ) {
          performAIAnalysis(button, issueId);
        }
      });
  }

  /**
   * Update the progress bar
   *
   * @param {number} percent - Percentage complete (0-100)
   * @param {string} stage - Current scan stage
   * @param {string} message - Status message
   */
  function updateProgressBar(percent, stage, message) {
    $("#scan-progress-container").show();
    $(".scan-progress-bar-fill").css("width", percent + "%");
    $(".scan-progress-text").text(percent + "%");

    var stageText = "";
    switch (stage) {
      case "core":
        stageText = "Scanning WordPress core files";
        break;
      case "plugins":
        stageText = "Scanning plugin files";
        break;
      case "themes":
        stageText = "Scanning theme files";
        break;
      case "uploads":
        stageText = "Scanning uploads directory";
        break;
      case "ai_analysis":
        stageText = "Analyzing suspicious files with AI";
        break;
      default:
        stageText = "Scanning in progress";
    }

    var stageHtml =
      "<p><strong>" + stageText + "</strong>: " + message + "</p>";
    stageHtml += '<div class="scan-stage-list">';

    for (var i = 0; i < stages.length; i++) {
      var status = "pending";
      var statusText = "Pending";

      // Set stage status
      if (stages[i] === stage) {
        status = "in-progress";
        statusText = "In Progress";
      } else if (stages.indexOf(stage) > stages.indexOf(stages[i])) {
        status = "completed";
        statusText = "Completed";
      }

      var stageName = "";
      switch (stages[i]) {
        case "core":
          stageName = "WordPress Core";
          break;
        case "plugins":
          stageName = "Plugins";
          break;
        case "themes":
          stageName = "Themes";
          break;
        case "uploads":
          stageName = "Uploads Directory";
          break;
        case "ai_analysis":
          stageName = "AI Analysis";
          break;
      }

      stageHtml += '<div class="scan-stage-item">';
      stageHtml += '<span class="stage-name">' + stageName + "</span>";
      stageHtml +=
        '<span class="stage-status ' + status + '">' + statusText + "</span>";
      stageHtml += "</div>";
    }

    stageHtml += "</div>";
    $("#scan-stage-info").html(stageHtml);
  }

  /**
   * Calculate overall progress based on stage progress
   */
  function calculateOverallProgress() {
    var overall = 0;
    for (var stage in stageProgress) {
      if (stageProgress.hasOwnProperty(stage)) {
        overall += stageProgress[stage] * stageWeights[stage];
      }
    }
    return Math.round(overall);
  }

  /**
   * Start a new scan
   */
  function startScan() {
    const button = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    // Reset progress tracking
    overallProgress = 0;
    currentStage = "";
    for (var stage in stageProgress) {
      stageProgress[stage] = 0;
    }

    // Show initial progress bar at 0%
    updateProgressBar(0, "", "Preparing scan");

    // Disable buttons and show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.scanning || "Scanning...");

    if (resumeButton.length) {
      resumeButton.prop("disabled", true);
    }

    statusArea.html(
      '<div class="notice notice-info"><p>Starting security scan... <span class="loading-spinner"></span></p></div>'
    );

    // AJAX request to start scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_start_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan started successfully!</p></div>'
          );
          pollScanStatus(response.data.scan_id);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function (xhr) {
        // Check for timeout (504)
        if (xhr.status === 504) {
          statusArea.html(
            '<div class="notice notice-error"><p>The scan timed out. This usually happens on larger sites. The scan will continue in the background. Please check back later for results, or try refreshing the page.</p></div>'
          );

          // Continue polling despite the timeout
          pollScanStatus(null);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Server error. Please try again.</p></div>'
          );
        }
      },
    });
  }

  /**
   * Resume an interrupted scan
   */
  function resumeScan() {
    const button = $("#resume-scan-button");
    const startButton = $("#start-scan-button");
    const statusArea = $("#scan-status-area");

    // Reset progress tracking
    overallProgress = 0;
    currentStage = "";
    for (var stage in stageProgress) {
      stageProgress[stage] = 0;
    }

    // Show initial progress bar
    updateProgressBar(0, "", "Preparing to resume scan");

    // Disable buttons and show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.scanning || "Resuming...");
    startButton.prop("disabled", true);

    statusArea.html(
      '<div class="notice notice-info"><p>Resuming security scan... <span class="loading-spinner"></span></p></div>'
    );

    // AJAX request to resume scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_resume_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan resumed successfully!</p></div>'
          );
          pollScanStatus(response.data.scan_id);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function (xhr) {
        // Check for timeout (504)
        if (xhr.status === 504) {
          statusArea.html(
            '<div class="notice notice-error"><p>The scan timed out. This usually happens on larger sites. The scan will continue in the background. Please check back later for results, or try refreshing the page.</p></div>'
          );

          // Continue polling despite the timeout
          pollScanStatus(null);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Server error. Please try again.</p></div>'
          );
        }
      },
    });
  }

  /**
   * Stop the current scan
   */
  function stopScan() {
    const button = $("#stop-scan-button");
    const startButton = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    button.prop("disabled", true);
    button.text("Stopping...");

    // AJAX request to stop scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_stop_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        button.prop("disabled", false);
        button.text(twss_data.i18n.stop_scan || "Stop Scan");

        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan stopped successfully.</p></div>'
          );

          // Update UI to reflect scan stopped state
          $("#scan-progress-container").hide();
          resumeButton.prop("disabled", false);
          resumeButton.text(twss_data.i18n.resume_scan || "Resume Scan");
        } else {
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function () {
        button.prop("disabled", false);
        button.text(twss_data.i18n.stop_scan || "Stop Scan");
        alert("Error stopping scan. Please try again.");
      },
    });
  }

  /**
   * Clear all issues from the issues table
   */
  function clearAllIssues() {
    if (confirm("Are you sure you want to clear all issues?")) {
      const button = $("#clear-all-issues-button");
      button.prop("disabled", true).text("Clearing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_all_issues",
          nonce: twss_data.nonce,
        },
        success: function (response) {
          button.prop("disabled", false).text("Clear All Issues");

          if (response.success) {
            // Show success message
            alert("All issues cleared successfully.");
            location.reload(); // Reload page to update issues table
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          button.prop("disabled", false).text("Clear All Issues");
          alert("Error clearing issues. Please try again.");
        },
      });
    }
  }

  /**
   * Clear issues for a specific scan
   *
   * @param {number} scanId - The scan ID
   */
  function clearScanIssues(scanId) {
    if (confirm("Are you sure you want to clear issues for this scan?")) {
      const button = $(
        ".clear-scan-issues-button[data-scan-id='" + scanId + "']"
      );
      button.prop("disabled", true).text("Clearing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_scan_issues",
          nonce: twss_data.nonce,
          scan_id: scanId,
        },
        success: function (response) {
          button.prop("disabled", false).text("Clear Scan Issues");

          if (response.success) {
            // Show success message
            alert("Scan issues cleared successfully.");
            location.reload(); // Reload page to update issues table
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          button.prop("disabled", false).text("Clear Scan Issues");
          alert("Error clearing scan issues. Please try again.");
        },
      });
    }
  }

  /**
   * Setup AI connection testing functionality
   */
  function setupAIConnectionTesting() {
    // Test OpenAI API Key
    $(document).on("click", "#test-openai-api", function (e) {
      e.preventDefault();
      var button = $(this);
      var apiKey = $("#twss_openai_api_key").val();
      var statusSpan = $("#openai-api-status");

      if (!apiKey) {
        statusSpan.html(
          '<span style="color: #d63638;">Please enter an API key first</span>'
        );
        return;
      }

      button.prop("disabled", true).text("Testing...");
      statusSpan.html(
        '<span style="color: #FF7342;">Testing connection...</span>'
      );

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_test_openai_api",
          api_key: apiKey,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            statusSpan.html(
              '<span style="color: #46b450;">✓ ' +
                response.data.message +
                "</span>"
            );
          } else {
            statusSpan.html(
              '<span style="color: #d63638;">✗ ' +
                response.data.message +
                "</span>"
            );
          }
        },
        error: function () {
          statusSpan.html(
            '<span style="color: #d63638;">✗ Connection failed</span>'
          );
        },
        complete: function () {
          button.prop("disabled", false).text("Test API Key");
        },
      });
    });

    // Test Gemini API Key
    $(document).on("click", "#test-gemini-api", function (e) {
      e.preventDefault();
      var button = $(this);
      var apiKey = $("#twss_gemini_api_key").val();
      var statusSpan = $("#gemini-api-status");

      if (!apiKey) {
        statusSpan.html(
          '<span style="color: #d63638;">Please enter an API key first</span>'
        );
        return;
      }

      button.prop("disabled", true).text("Testing...");
      statusSpan.html(
        '<span style="color: #FF7342;">Testing connection...</span>'
      );

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_test_gemini_api",
          api_key: apiKey,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            statusSpan.html(
              '<span style="color: #46b450;">✓ ' +
                response.data.message +
                "</span>"
            );
          } else {
            statusSpan.html(
              '<span style="color: #d63638;">✗ ' +
                response.data.message +
                "</span>"
            );
          }
        },
        error: function () {
          statusSpan.html(
            '<span style="color: #d63638;">✗ Connection failed</span>'
          );
        },
        complete: function () {
          button.prop("disabled", false).text("Test API Key");
        },
      });
    });
  }

  /**
   * Setup OAuth flow handlers
   */
  function setupOAuthHandlers() {
    // OAuth connection handlers
    $(document).on("click", "#connect-openai-oauth", function (e) {
      e.preventDefault();
      initiateOAuthFlow("openai");
    });

    $(document).on("click", "#disconnect-openai-oauth", function (e) {
      e.preventDefault();
      disconnectOAuth("openai");
    });

    $(document).on("click", "#connect-gemini-oauth", function (e) {
      e.preventDefault();
      initiateOAuthFlow("gemini");
    });

    $(document).on("click", "#disconnect-gemini-oauth", function (e) {
      e.preventDefault();
      disconnectOAuth("gemini");
    });

    function initiateOAuthFlow(provider) {
      // Get OAuth URL from server
      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_get_oauth_url",
          provider: provider,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success && response.data.url) {
            // Open OAuth popup with the proper URL
            var popup = window.open(
              response.data.url,
              "oauth_popup",
              "width=600,height=600,scrollbars=yes,resizable=yes"
            );

            // Listen for OAuth completion
            var checkClosed = setInterval(function () {
              if (popup.closed) {
                clearInterval(checkClosed);
                location.reload(); // Refresh to show connected status
              }
            }, 1000);
          } else {
            alert(
              "Error: " +
                (response.data ? response.data.message : "OAuth not configured")
            );
          }
        },
        error: function () {
          alert("Error connecting to OAuth service. Please try again.");
        },
      });
    }

    function disconnectOAuth(provider) {
      if (
        confirm("Are you sure you want to disconnect from " + provider + "?")
      ) {
        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_disconnect_oauth",
            provider: provider,
            nonce: twss_data.nonce,
          },
          success: function (response) {
            if (response.success) {
              location.reload();
            } else {
              alert("Error disconnecting: " + response.data.message);
            }
          },
        });
      }
    }
  }

  /**
   * Setup bulk actions for scan results
   */
  function setupBulkActions() {
    // Bulk action handlers
    $(document).on("click", "#bulk-fix-selected", function (e) {
      e.preventDefault();
      performBulkAction("fix");
    });

    $(document).on("click", "#bulk-quarantine-selected", function (e) {
      e.preventDefault();
      performBulkAction("quarantine");
    });

    $(document).on("click", "#bulk-delete-selected", function (e) {
      e.preventDefault();
      performBulkAction("delete");
    });

    $(document).on("click", "#bulk-whitelist-selected", function (e) {
      e.preventDefault();
      performBulkAction("whitelist");
    });

    // Select all checkbox
    $(document).on("change", "#select-all-files", function () {
      $(".file-checkbox").prop("checked", $(this).prop("checked"));
      updateBulkActionButtons();
    });

    // Individual file checkboxes
    $(document).on("change", ".file-checkbox", function () {
      updateBulkActionButtons();
    });

    function performBulkAction(action) {
      var selectedFiles = [];
      $(".file-checkbox:checked").each(function () {
        selectedFiles.push($(this).val());
      });

      if (selectedFiles.length === 0) {
        alert("Please select at least one file.");
        return;
      }

      var confirmMessage =
        "Are you sure you want to " +
        action +
        " " +
        selectedFiles.length +
        " selected file(s)?";
      if (action === "delete") {
        confirmMessage += " This action cannot be undone.";
      }

      if (!confirm(confirmMessage)) {
        return;
      }

      var button = $("#bulk-" + action + "-selected");
      var originalText = button.text();
      button.prop("disabled", true).text("Processing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_bulk_file_action",
          bulk_action: action,
          files: selectedFiles,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            alert(response.data.message);
            location.reload(); // Refresh to show updated results
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          alert("An error occurred while processing the request.");
        },
        complete: function () {
          button.prop("disabled", false).text(originalText);
        },
      });
    }

    function updateBulkActionButtons() {
      var selectedCount = $(".file-checkbox:checked").length;
      var buttons = $(
        "#bulk-fix-selected, #bulk-quarantine-selected, #bulk-delete-selected, #bulk-whitelist-selected"
      );

      if (selectedCount > 0) {
        buttons.prop("disabled", false);
        buttons.each(function () {
          var action = $(this)
            .attr("id")
            .replace("bulk-", "")
            .replace("-selected", "");
          $(this).text(
            action.charAt(0).toUpperCase() +
              action.slice(1) +
              " (" +
              selectedCount +
              ")"
          );
        });
      } else {
        buttons.prop("disabled", true);
        buttons.each(function () {
          var action = $(this)
            .attr("id")
            .replace("bulk-", "")
            .replace("-selected", "");
          $(this).text(action.charAt(0).toUpperCase() + action.slice(1));
        });
      }
    }
  }

  /**
   * Setup enhanced filtering for the issues page
   */
  function setupIssuesFiltering() {
    // Auto-submit filter form when selections change
    $(document).on("change", "#status_filter, #severity_filter", function () {
      var form = $("#issues-filter-form");
      if (form.length) {
        // Add loading state
        $(".filters-section").addClass("loading");
        form.submit();
      }
    });

    // Show filter counts (if we want to add this feature later)
    updateFilterCounts();

    // Keyboard navigation for pagination
    $(document).on("keydown", function (e) {
      if (
        e.target.tagName.toLowerCase() === "input" ||
        e.target.tagName.toLowerCase() === "textarea"
      ) {
        return; // Don't interfere with form inputs
      }

      var currentUrl = window.location.href;
      var currentPage = getCurrentPage();

      // Left arrow or 'p' for previous page
      if ((e.keyCode === 37 || e.keyCode === 80) && currentPage > 1) {
        e.preventDefault();
        var newUrl = updateUrlParameter(currentUrl, "paged", currentPage - 1);
        window.location.href = newUrl;
      }

      // Right arrow or 'n' for next page
      if (e.keyCode === 39 || e.keyCode === 78) {
        e.preventDefault();
        var nextPageLink = $('.pagination-links a:contains("Next")');
        if (nextPageLink.length) {
          window.location.href = nextPageLink.attr("href");
        }
      }
    });

    // Enhanced bulk selection with filter awareness
    updateBulkActionCounts();
  }

  /**
   * Update filter counts (placeholder for future enhancement)
   */
  function updateFilterCounts() {
    // This could show counts next to each filter option
    // e.g., "High (15)" instead of just "High"
    // Implementation would require AJAX call to get counts
  }

  /**
   * Get current page number from URL
   */
  function getCurrentPage() {
    var urlParams = new URLSearchParams(window.location.search);
    return parseInt(urlParams.get("paged")) || 1;
  }

  /**
   * Update URL parameter
   */
  function updateUrlParameter(url, param, value) {
    var urlParts = url.split("?");
    var baseUrl = urlParts[0];
    var params = new URLSearchParams(urlParts[1] || "");
    params.set(param, value);
    return baseUrl + "?" + params.toString();
  }

  /**
   * Enhanced bulk action count updates
   */
  function updateBulkActionCounts() {
    var selectedCount = $(".file-checkbox:checked").length;
    var totalVisible = $(".file-checkbox").length;

    // Update bulk action button text with context
    if (selectedCount > 0) {
      var buttons = $(
        "#bulk-fix-selected, #bulk-quarantine-selected, #bulk-delete-selected, #bulk-whitelist-selected"
      );
      buttons.each(function () {
        var action = $(this)
          .attr("id")
          .replace("bulk-", "")
          .replace("-selected", "");
        var actionText = action.charAt(0).toUpperCase() + action.slice(1);
        $(this).text(
          actionText + " (" + selectedCount + " of " + totalVisible + ")"
        );
      });
    }
  }

  /**
   * Update the progress bar
   *
   * @param {number} percent - Percentage complete (0-100)
   * @param {string} stage - Current scan stage
   * @param {string} message - Status message
   */
  function updateProgressBar(percent, stage, message) {
    $("#scan-progress-container").show();
    $(".scan-progress-bar-fill").css("width", percent + "%");
    $(".scan-progress-text").text(percent + "%");

    var stageText = "";
    switch (stage) {
      case "core":
        stageText = "Scanning WordPress core files";
        break;
      case "plugins":
        stageText = "Scanning plugin files";
        break;
      case "themes":
        stageText = "Scanning theme files";
        break;
      case "uploads":
        stageText = "Scanning uploads directory";
        break;
      case "ai_analysis":
        stageText = "Analyzing suspicious files with AI";
        break;
      default:
        stageText = "Scanning in progress";
    }

    var stageHtml =
      "<p><strong>" + stageText + "</strong>: " + message + "</p>";
    stageHtml += '<div class="scan-stage-list">';

    for (var i = 0; i < stages.length; i++) {
      var status = "pending";
      var statusText = "Pending";

      // Set stage status
      if (stages[i] === stage) {
        status = "in-progress";
        statusText = "In Progress";
      } else if (stages.indexOf(stage) > stages.indexOf(stages[i])) {
        status = "completed";
        statusText = "Completed";
      }

      var stageName = "";
      switch (stages[i]) {
        case "core":
          stageName = "WordPress Core";
          break;
        case "plugins":
          stageName = "Plugins";
          break;
        case "themes":
          stageName = "Themes";
          break;
        case "uploads":
          stageName = "Uploads Directory";
          break;
        case "ai_analysis":
          stageName = "AI Analysis";
          break;
      }

      stageHtml += '<div class="scan-stage-item">';
      stageHtml += '<span class="stage-name">' + stageName + "</span>";
      stageHtml +=
        '<span class="stage-status ' + status + '">' + statusText + "</span>";
      stageHtml += "</div>";
    }

    stageHtml += "</div>";
    $("#scan-stage-info").html(stageHtml);
  }

  /**
   * Calculate overall progress based on stage progress
   */
  function calculateOverallProgress() {
    var overall = 0;
    for (var stage in stageProgress) {
      if (stageProgress.hasOwnProperty(stage)) {
        overall += stageProgress[stage] * stageWeights[stage];
      }
    }
    return Math.round(overall);
  }

  /**
   * Start a new scan
   */
  function startScan() {
    const button = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    // Reset progress tracking
    overallProgress = 0;
    currentStage = "";
    for (var stage in stageProgress) {
      stageProgress[stage] = 0;
    }

    // Show initial progress bar at 0%
    updateProgressBar(0, "", "Preparing scan");

    // Disable buttons and show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.scanning || "Scanning...");

    if (resumeButton.length) {
      resumeButton.prop("disabled", true);
    }

    statusArea.html(
      '<div class="notice notice-info"><p>Starting security scan... <span class="loading-spinner"></span></p></div>'
    );

    // AJAX request to start scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_start_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan started successfully!</p></div>'
          );
          pollScanStatus(response.data.scan_id);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function (xhr) {
        // Check for timeout (504)
        if (xhr.status === 504) {
          statusArea.html(
            '<div class="notice notice-error"><p>The scan timed out. This usually happens on larger sites. The scan will continue in the background. Please check back later for results, or try refreshing the page.</p></div>'
          );

          // Continue polling despite the timeout
          pollScanStatus(null);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Server error. Please try again.</p></div>'
          );
        }
      },
    });
  }

  /**
   * Resume an interrupted scan
   */
  function resumeScan() {
    const button = $("#resume-scan-button");
    const startButton = $("#start-scan-button");
    const statusArea = $("#scan-status-area");

    // Reset progress tracking
    overallProgress = 0;
    currentStage = "";
    for (var stage in stageProgress) {
      stageProgress[stage] = 0;
    }

    // Show initial progress bar
    updateProgressBar(0, "", "Preparing to resume scan");

    // Disable buttons and show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.scanning || "Resuming...");
    startButton.prop("disabled", true);

    statusArea.html(
      '<div class="notice notice-info"><p>Resuming security scan... <span class="loading-spinner"></span></p></div>'
    );

    // AJAX request to resume scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_resume_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan resumed successfully!</p></div>'
          );
          pollScanStatus(response.data.scan_id);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function (xhr) {
        // Check for timeout (504)
        if (xhr.status === 504) {
          statusArea.html(
            '<div class="notice notice-error"><p>The scan timed out. This usually happens on larger sites. The scan will continue in the background. Please check back later for results, or try refreshing the page.</p></div>'
          );

          // Continue polling despite the timeout
          pollScanStatus(null);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Server error. Please try again.</p></div>'
          );
        }
      },
    });
  }

  /**
   * Stop the current scan
   */
  function stopScan() {
    const button = $("#stop-scan-button");
    const startButton = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    button.prop("disabled", true);
    button.text("Stopping...");

    // AJAX request to stop scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_stop_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        button.prop("disabled", false);
        button.text(twss_data.i18n.stop_scan || "Stop Scan");

        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan stopped successfully.</p></div>'
          );

          // Update UI to reflect scan stopped state
          $("#scan-progress-container").hide();
          resumeButton.prop("disabled", false);
          resumeButton.text(twss_data.i18n.resume_scan || "Resume Scan");
        } else {
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function () {
        button.prop("disabled", false);
        button.text(twss_data.i18n.stop_scan || "Stop Scan");
        alert("Error stopping scan. Please try again.");
      },
    });
  }

  /**
   * Clear all issues from the issues table
   */
  function clearAllIssues() {
    if (confirm("Are you sure you want to clear all issues?")) {
      const button = $("#clear-all-issues-button");
      button.prop("disabled", true).text("Clearing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_all_issues",
          nonce: twss_data.nonce,
        },
        success: function (response) {
          button.prop("disabled", false).text("Clear All Issues");

          if (response.success) {
            // Show success message
            alert("All issues cleared successfully.");
            location.reload(); // Reload page to update issues table
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          button.prop("disabled", false).text("Clear All Issues");
          alert("Error clearing issues. Please try again.");
        },
      });
    }
  }

  /**
   * Clear issues for a specific scan
   *
   * @param {number} scanId - The scan ID
   */
  function clearScanIssues(scanId) {
    if (confirm("Are you sure you want to clear issues for this scan?")) {
      const button = $(
        ".clear-scan-issues-button[data-scan-id='" + scanId + "']"
      );
      button.prop("disabled", true).text("Clearing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_scan_issues",
          nonce: twss_data.nonce,
          scan_id: scanId,
        },
        success: function (response) {
          button.prop("disabled", false).text("Clear Scan Issues");

          if (response.success) {
            // Show success message
            alert("Scan issues cleared successfully.");
            location.reload(); // Reload page to update issues table
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          button.prop("disabled", false).text("Clear Scan Issues");
          alert("Error clearing scan issues. Please try again.");
        },
      });
    }
  }

  /**
   * Setup AI connection testing functionality
   */
  function setupAIConnectionTesting() {
    // Test OpenAI API Key
    $(document).on("click", "#test-openai-api", function (e) {
      e.preventDefault();
      var button = $(this);
      var apiKey = $("#twss_openai_api_key").val();
      var statusSpan = $("#openai-api-status");

      if (!apiKey) {
        statusSpan.html(
          '<span style="color: #d63638;">Please enter an API key first</span>'
        );
        return;
      }

      button.prop("disabled", true).text("Testing...");
      statusSpan.html(
        '<span style="color: #FF7342;">Testing connection...</span>'
      );

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_test_openai_api",
          api_key: apiKey,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            statusSpan.html(
              '<span style="color: #46b450;">✓ ' +
                response.data.message +
                "</span>"
            );
          } else {
            statusSpan.html(
              '<span style="color: #d63638;">✗ ' +
                response.data.message +
                "</span>"
            );
          }
        },
        error: function () {
          statusSpan.html(
            '<span style="color: #d63638;">✗ Connection failed</span>'
          );
        },
        complete: function () {
          button.prop("disabled", false).text("Test API Key");
        },
      });
    });

    // Test Gemini API Key
    $(document).on("click", "#test-gemini-api", function (e) {
      e.preventDefault();
      var button = $(this);
      var apiKey = $("#twss_gemini_api_key").val();
      var statusSpan = $("#gemini-api-status");

      if (!apiKey) {
        statusSpan.html(
          '<span style="color: #d63638;">Please enter an API key first</span>'
        );
        return;
      }

      button.prop("disabled", true).text("Testing...");
      statusSpan.html(
        '<span style="color: #FF7342;">Testing connection...</span>'
      );

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_test_gemini_api",
          api_key: apiKey,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            statusSpan.html(
              '<span style="color: #46b450;">✓ ' +
                response.data.message +
                "</span>"
            );
          } else {
            statusSpan.html(
              '<span style="color: #d63638;">✗ ' +
                response.data.message +
                "</span>"
            );
          }
        },
        error: function () {
          statusSpan.html(
            '<span style="color: #d63638;">✗ Connection failed</span>'
          );
        },
        complete: function () {
          button.prop("disabled", false).text("Test API Key");
        },
      });
    });
  }

  /**
   * Setup OAuth flow handlers
   */
  function setupOAuthHandlers() {
    // OAuth connection handlers
    $(document).on("click", "#connect-openai-oauth", function (e) {
      e.preventDefault();
      initiateOAuthFlow("openai");
    });

    $(document).on("click", "#disconnect-openai-oauth", function (e) {
      e.preventDefault();
      disconnectOAuth("openai");
    });

    $(document).on("click", "#connect-gemini-oauth", function (e) {
      e.preventDefault();
      initiateOAuthFlow("gemini");
    });

    $(document).on("click", "#disconnect-gemini-oauth", function (e) {
      e.preventDefault();
      disconnectOAuth("gemini");
    });

    function initiateOAuthFlow(provider) {
      // Get OAuth URL from server
      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_get_oauth_url",
          provider: provider,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success && response.data.url) {
            // Open OAuth popup with the proper URL
            var popup = window.open(
              response.data.url,
              "oauth_popup",
              "width=600,height=600,scrollbars=yes,resizable=yes"
            );

            // Listen for OAuth completion
            var checkClosed = setInterval(function () {
              if (popup.closed) {
                clearInterval(checkClosed);
                location.reload(); // Refresh to show connected status
              }
            }, 1000);
          } else {
            alert(
              "Error: " +
                (response.data ? response.data.message : "OAuth not configured")
            );
          }
        },
        error: function () {
          alert("Error connecting to OAuth service. Please try again.");
        },
      });
    }

    function disconnectOAuth(provider) {
      if (
        confirm("Are you sure you want to disconnect from " + provider + "?")
      ) {
        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_disconnect_oauth",
            provider: provider,
            nonce: twss_data.nonce,
          },
          success: function (response) {
            if (response.success) {
              location.reload();
            } else {
              alert("Error disconnecting: " + response.data.message);
            }
          },
        });
      }
    }
  }

  /**
   * Setup bulk actions for scan results
   */
  function setupBulkActions() {
    // Bulk action handlers
    $(document).on("click", "#bulk-fix-selected", function (e) {
      e.preventDefault();
      performBulkAction("fix");
    });

    $(document).on("click", "#bulk-quarantine-selected", function (e) {
      e.preventDefault();
      performBulkAction("quarantine");
    });

    $(document).on("click", "#bulk-delete-selected", function (e) {
      e.preventDefault();
      performBulkAction("delete");
    });

    $(document).on("click", "#bulk-whitelist-selected", function (e) {
      e.preventDefault();
      performBulkAction("whitelist");
    });

    // Select all checkbox
    $(document).on("change", "#select-all-files", function () {
      $(".file-checkbox").prop("checked", $(this).prop("checked"));
      updateBulkActionButtons();
    });

    // Individual file checkboxes
    $(document).on("change", ".file-checkbox", function () {
      updateBulkActionButtons();
    });

    function performBulkAction(action) {
      var selectedFiles = [];
      $(".file-checkbox:checked").each(function () {
        selectedFiles.push($(this).val());
      });

      if (selectedFiles.length === 0) {
        alert("Please select at least one file.");
        return;
      }

      var confirmMessage =
        "Are you sure you want to " +
        action +
        " " +
        selectedFiles.length +
        " selected file(s)?";
      if (action === "delete") {
        confirmMessage += " This action cannot be undone.";
      }

      if (!confirm(confirmMessage)) {
        return;
      }

      var button = $("#bulk-" + action + "-selected");
      var originalText = button.text();
      button.prop("disabled", true).text("Processing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_bulk_file_action",
          bulk_action: action,
          files: selectedFiles,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            alert(response.data.message);
            location.reload(); // Refresh to show updated results
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          alert("An error occurred while processing the request.");
        },
        complete: function () {
          button.prop("disabled", false).text(originalText);
        },
      });
    }

    function updateBulkActionButtons() {
      var selectedCount = $(".file-checkbox:checked").length;
      var buttons = $(
        "#bulk-fix-selected, #bulk-quarantine-selected, #bulk-delete-selected, #bulk-whitelist-selected"
      );

      if (selectedCount > 0) {
        buttons.prop("disabled", false);
        buttons.each(function () {
          var action = $(this)
            .attr("id")
            .replace("bulk-", "")
            .replace("-selected", "");
          $(this).text(
            action.charAt(0).toUpperCase() +
              action.slice(1) +
              " (" +
              selectedCount +
              ")"
          );
        });
      } else {
        buttons.prop("disabled", true);
        buttons.each(function () {
          var action = $(this)
            .attr("id")
            .replace("bulk-", "")
            .replace("-selected", "");
          $(this).text(action.charAt(0).toUpperCase() + action.slice(1));
        });
      }
    }
  }

  /**
   * Setup enhanced filtering for the issues page
   */
  function setupIssuesFiltering() {
    // Auto-submit filter form when selections change
    $(document).on("change", "#status_filter, #severity_filter", function () {
      var form = $("#issues-filter-form");
      if (form.length) {
        // Add loading state
        $(".filters-section").addClass("loading");
        form.submit();
      }
    });

    // Show filter counts (if we want to add this feature later)
    updateFilterCounts();

    // Keyboard navigation for pagination
    $(document).on("keydown", function (e) {
      if (
        e.target.tagName.toLowerCase() === "input" ||
        e.target.tagName.toLowerCase() === "textarea"
      ) {
        return; // Don't interfere with form inputs
      }

      var currentUrl = window.location.href;
      var currentPage = getCurrentPage();

      // Left arrow or 'p' for previous page
      if ((e.keyCode === 37 || e.keyCode === 80) && currentPage > 1) {
        e.preventDefault();
        var newUrl = updateUrlParameter(currentUrl, "paged", currentPage - 1);
        window.location.href = newUrl;
      }

      // Right arrow or 'n' for next page
      if (e.keyCode === 39 || e.keyCode === 78) {
        e.preventDefault();
        var nextPageLink = $('.pagination-links a:contains("Next")');
        if (nextPageLink.length) {
          window.location.href = nextPageLink.attr("href");
        }
      }
    });

    // Enhanced bulk selection with filter awareness
    updateBulkActionCounts();
  }

  /**
   * Update filter counts (placeholder for future enhancement)
   */
  function updateFilterCounts() {
    // This could show counts next to each filter option
    // e.g., "High (15)" instead of just "High"
    // Implementation would require AJAX call to get counts
  }

  /**
   * Get current page number from URL
   */
  function getCurrentPage() {
    var urlParams = new URLSearchParams(window.location.search);
    return parseInt(urlParams.get("paged")) || 1;
  }

  /**
   * Update URL parameter
   */
  function updateUrlParameter(url, param, value) {
    var urlParts = url.split("?");
    var baseUrl = urlParts[0];
    var params = new URLSearchParams(urlParts[1] || "");
    params.set(param, value);
    return baseUrl + "?" + params.toString();
  }

  /**
   * Enhanced bulk action count updates
   */
  function updateBulkActionCounts() {
    var selectedCount = $(".file-checkbox:checked").length;
    var totalVisible = $(".file-checkbox").length;

    // Update bulk action button text with context
    if (selectedCount > 0) {
      var buttons = $(
        "#bulk-fix-selected, #bulk-quarantine-selected, #bulk-delete-selected, #bulk-whitelist-selected"
      );
      buttons.each(function () {
        var action = $(this)
          .attr("id")
          .replace("bulk-", "")
          .replace("-selected", "");
        var actionText = action.charAt(0).toUpperCase() + action.slice(1);
        $(this).text(
          actionText + " (" + selectedCount + " of " + totalVisible + ")"
        );
      });
    }
  }

  /**
   * Update the progress bar
   *
   * @param {number} percent - Percentage complete (0-100)
   * @param {string} stage - Current scan stage
   * @param {string} message - Status message
   */
  function updateProgressBar(percent, stage, message) {
    $("#scan-progress-container").show();
    $(".scan-progress-bar-fill").css("width", percent + "%");
    $(".scan-progress-text").text(percent + "%");

    var stageText = "";
    switch (stage) {
      case "core":
        stageText = "Scanning WordPress core files";
        break;
      case "plugins":
        stageText = "Scanning plugin files";
        break;
      case "themes":
        stageText = "Scanning theme files";
        break;
      case "uploads":
        stageText = "Scanning uploads directory";
        break;
      case "ai_analysis":
        stageText = "Analyzing suspicious files with AI";
        break;
      default:
        stageText = "Scanning in progress";
    }

    var stageHtml =
      "<p><strong>" + stageText + "</strong>: " + message + "</p>";
    stageHtml += '<div class="scan-stage-list">';

    for (var i = 0; i < stages.length; i++) {
      var status = "pending";
      var statusText = "Pending";

      // Set stage status
      if (stages[i] === stage) {
        status = "in-progress";
        statusText = "In Progress";
      } else if (stages.indexOf(stage) > stages.indexOf(stages[i])) {
        status = "completed";
        statusText = "Completed";
      }

      var stageName = "";
      switch (stages[i]) {
        case "core":
          stageName = "WordPress Core";
          break;
        case "plugins":
          stageName = "Plugins";
          break;
        case "themes":
          stageName = "Themes";
          break;
        case "uploads":
          stageName = "Uploads Directory";
          break;
        case "ai_analysis":
          stageName = "AI Analysis";
          break;
      }

      stageHtml += '<div class="scan-stage-item">';
      stageHtml += '<span class="stage-name">' + stageName + "</span>";
      stageHtml +=
        '<span class="stage-status ' + status + '">' + statusText + "</span>";
      stageHtml += "</div>";
    }

    stageHtml += "</div>";
    $("#scan-stage-info").html(stageHtml);
  }

  /**
   * Calculate overall progress based on stage progress
   */
  function calculateOverallProgress() {
    var overall = 0;
    for (var stage in stageProgress) {
      if (stageProgress.hasOwnProperty(stage)) {
        overall += stageProgress[stage] * stageWeights[stage];
      }
    }
    return Math.round(overall);
  }

  /**
   * Start a new scan
   */
  function startScan() {
    const button = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    // Reset progress tracking
    overallProgress = 0;
    currentStage = "";
    for (var stage in stageProgress) {
      stageProgress[stage] = 0;
    }

    // Show initial progress bar at 0%
    updateProgressBar(0, "", "Preparing scan");

    // Disable buttons and show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.scanning || "Scanning...");

    if (resumeButton.length) {
      resumeButton.prop("disabled", true);
    }

    statusArea.html(
      '<div class="notice notice-info"><p>Starting security scan... <span class="loading-spinner"></span></p></div>'
    );

    // AJAX request to start scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_start_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan started successfully!</p></div>'
          );
          pollScanStatus(response.data.scan_id);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function (xhr) {
        // Check for timeout (504)
        if (xhr.status === 504) {
          statusArea.html(
            '<div class="notice notice-error"><p>The scan timed out. This usually happens on larger sites. The scan will continue in the background. Please check back later for results, or try refreshing the page.</p></div>'
          );

          // Continue polling despite the timeout
          pollScanStatus(null);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Server error. Please try again.</p></div>'
          );
        }
      },
    });
  }

  /**
   * Resume an interrupted scan
   */
  function resumeScan() {
    const button = $("#resume-scan-button");
    const startButton = $("#start-scan-button");
    const statusArea = $("#scan-status-area");

    // Reset progress tracking
    overallProgress = 0;
    currentStage = "";
    for (var stage in stageProgress) {
      stageProgress[stage] = 0;
    }

    // Show initial progress bar
    updateProgressBar(0, "", "Preparing to resume scan");

    // Disable buttons and show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.scanning || "Resuming...");
    startButton.prop("disabled", true);

    statusArea.html(
      '<div class="notice notice-info"><p>Resuming security scan... <span class="loading-spinner"></span></p></div>'
    );

    // AJAX request to resume scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_resume_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan resumed successfully!</p></div>'
          );
          pollScanStatus(response.data.scan_id);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function (xhr) {
        // Check for timeout (504)
        if (xhr.status === 504) {
          statusArea.html(
            '<div class="notice notice-error"><p>The scan timed out. This usually happens on larger sites. The scan will continue in the background. Please check back later for results, or try refreshing the page.</p></div>'
          );

          // Continue polling despite the timeout
          pollScanStatus(null);
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

          $("#scan-progress-container").hide();
          statusArea.html(
            '<div class="notice notice-error"><p>Server error. Please try again.</p></div>'
          );
        }
      },
    });
  }

  /**
   * Stop the current scan
   */
  function stopScan() {
    const button = $("#stop-scan-button");
    const startButton = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    button.prop("disabled", true);
    button.text("Stopping...");

    // AJAX request to stop scan
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_stop_scan",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        button.prop("disabled", false);
        button.text(twss_data.i18n.stop_scan || "Stop Scan");

        if (response.success) {
          statusArea.html(
            '<div class="notice notice-success"><p>Scan stopped successfully.</p></div>'
          );

          // Update UI to reflect scan stopped state
          $("#scan-progress-container").hide();
          resumeButton.prop("disabled", false);
          resumeButton.text(twss_data.i18n.resume_scan || "Resume Scan");
        } else {
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
        }
      },
      error: function () {
        button.prop("disabled", false);
        button.text(twss_data.i18n.stop_scan || "Stop Scan");
        alert("Error stopping scan. Please try again.");
      },
    });
  }

  /**
   * Clear all issues from the issues table
   */
  function clearAllIssues() {
    if (confirm("Are you sure you want to clear all issues?")) {
      const button = $("#clear-all-issues-button");
      button.prop("disabled", true).text("Clearing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_all_issues",
          nonce: twss_data.nonce,
        },
        success: function (response) {
          button.prop("disabled", false).text("Clear All Issues");

          if (response.success) {
            // Show success message
            alert("All issues cleared successfully.");
            location.reload(); // Reload page to update issues table
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          button.prop("disabled", false).text("Clear All Issues");
          alert("Error clearing issues. Please try again.");
        },
      });
    }
  }

  /**
   * Clear issues for a specific scan
   *
   * @param {number} scanId - The scan ID
   */
  function clearScanIssues(scanId) {
    if (confirm("Are you sure you want to clear issues for this scan?")) {
      const button = $(
        ".clear-scan-issues-button[data-scan-id='" + scanId + "']"
      );
      button.prop("disabled", true).text("Clearing...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_scan_issues",
          nonce: twss_data.nonce,
          scan_id: scanId,
        },
        success: function (response) {
          button.prop("disabled", false).text("Clear Scan Issues");

          if (response.success) {
            // Show success message
            alert("Scan issues cleared successfully.");
            location.reload(); // Reload page to update issues table
          } else {
            alert("Error: " + response.data.message);
          }
        },
        error: function () {
          button.prop("disabled", false).text("Clear Scan Issues");
          alert("Error clearing scan issues. Please try again.");
        },
      });
    }
  }

  /**
   * Setup AI connection testing functionality
   */
  function setupAIConnectionTesting() {
    // Test OpenAI API Key
    $(document).on("click", "#test-openai-api", function (e) {
      e.preventDefault();
      var button = $(this);
      var apiKey = $("#twss_openai_api_key").val();
      var statusSpan = $("#openai-api-status");

      if (!apiKey) {
        statusSpan.html(
          '<span style="color: #d63638;">Please enter an API key first</span>'
        );
        return;
      }

      button.prop("disabled", true).text("Testing...");
      statusSpan.html(
        '<span style="color: #FF7342;">Testing connection...</span>'
      );

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_test_openai_api",
          api_key: apiKey,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            statusSpan.html(
              '<span style="color: #46b450;">✓ ' +
                response.data.message +
                "</span>"
            );
          } else {
            statusSpan.html(
              '<span style="color: #d63638;">✗ ' +
                response.data.message +
                "</span>"
            );
          }
        },
        error: function () {
          statusSpan.html(
            '<span style="color: #d63638;">✗ Connection failed</span>'
          );
        },
        complete: function () {
          button.prop("disabled", false).text("Test API Key");
        },
      });
    });

    // Test Gemini API Key
    $(document).on("click", "#test-gemini-api", function (e) {
      e.preventDefault();
      var button = $(this);
      var apiKey = $("#twss_gemini_api_key").val();
      var statusSpan = $("#gemini-api-status");

      if (!apiKey) {
        statusSpan.html(
          '<span style="color: #d63638;">Please enter an API key first</span>'
        );
        return;
      }

      button.prop("disabled", true).text("Testing...");
      statusSpan.html(
        '<span style="color: #FF7342;">Testing connection...</span>'
      );

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_test_gemini_api",
          api_key: apiKey,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success) {
            statusSpan.html(
              '<span style="color: #46b450;">✓ ' +
                response.data.message +
                "</span>"
            );
          } else {
            statusSpan.html(
              '<span style="color: #d63638;">✗ ' +
                response.data.message +
                "</span>"
            );
          }
        },
        error: function () {
          statusSpan.html(
            '<span style="color: #d63638;">✗ Connection failed</span>'
          );
        },
        complete: function () {
          button.prop("disabled", false).text("Test API Key");
        },
      });
    });
  }

  /**
   * Setup OAuth flow handlers
   */
  function setupOAuthHandlers() {
    // OAuth connection handlers
    $(document).on("click", "#connect-openai-oauth", function (e) {
      e.preventDefault();
      initiateOAuthFlow("openai");
    });

    $(document).on("click", "#disconnect-openai-oauth", function (e) {
      e.preventDefault();
      disconnectOAuth("openai");
    });

    $(document).on("click", "#connect-gemini-oauth", function (e) {
      e.preventDefault();
      initiateOAuthFlow("gemini");
    });

    $(document).on("click", "#disconnect-gemini-oauth", function (e) {
      e.preventDefault();
      disconnectOAuth("gemini");
    });

    function initiateOAuthFlow(provider) {
      // Get OAuth URL from server
      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_get_oauth_url",
          provider: provider,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success && response.data.url) {
            // Open OAuth popup with the proper URL
            var popup = window.open(
              response.data.url,
              "oauth_popup",
              "width=600,height=600,scrollbars=yes,resizable=yes"
            );

            // Listen for OAuth completion
            var checkClosed = setInterval(function () {
              if (popup.closed) {
                clearInterval(checkClosed);
                location.reload(); // Refresh to show connected status
              }
            }, 1000);
          } else {
            alert(
              "Error: " +
                (response.data ? response.data.message : "OAuth not configured")
            );
          }
        },
        error: function () {
          alert("Error connecting to OAuth service. Please try again.");
        },
      });
    }

    function disconnectOAuth(provider) {
      if (
        confirm("Are you sure you want to disconnect from " + provider + "?")
      ) {
        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_disconnect_oauth",
            provider: provider,
            nonce: twss_data.nonce,
          },
          success: function (response) {
            if (response.success) {
              location.reload();
            } else {
              alert("Error disconnecting: " + response.data.message);
            }
          },
        });
      }
    }
  }

  /**
   * Setup bulk actions for scan results
   */
  function setupBulkActions() {
    // Bulk action handlers
    $(document).on("click", "#bulk-fix-selected", function (e) {
      e.preventDefault();
      performBulkAction("fix");
    });

    $(document).on("click", "#bulk-quarantine-selected", function (e) {
      e.preventDefault();
      performBulkAction("quarantine");
    });

    $(document).on("click", "#bulk-delete-selected", function (e) {
      e.preventDefault();
      performBulkAction("delete");
    });

    $(document).on("click", "#bulk-whitelist-selected", function (e) {
      e.preventDefault();
      performBulkAction("whitelist");
    });

    // Select all checkbox
    $(document).on("change", "#select-all-files", function () {
      $(".file-checkbox").prop("checked", $(this).prop("checked"));
      updateBulkActionButtons();
    });

    // Individual file checkboxes
    $(document).on("change", ".file-checkbox", function () {
      updateBulkActionButtons();
    });

    function performBulkAction(action) {
      var selectedFiles = [];
      $(".file-checkbox:checked").each(function () {
        selectedFiles.push($(this).val());
      });

      if (selectedFiles.length === 0) {
        alert("Please select at least one file.");
        return;
      }

      if (
        confirm("Are you sure you want to " + action + " the selected files?")
      ) {
        // Perform the bulk action via AJAX
        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_bulk_file_action",
            bulk_action: action,
            selected_files: selectedFiles,
            nonce: twss_data.nonce,
          },
          success: function (response) {
            if (response.success) {
              location.reload();
            } else {
              alert("Error: " + (response.data.message || "Unknown error"));
            }
          },
          error: function () {
            alert("Error performing bulk action. Please try again.");
          },
        });
      }
    }
  }

  /**
   * Perform AI analysis on a specific issue
   *
   * @param {jQuery} button - The button that was clicked
   * @param {number} issueId - The issue ID to analyze
   */
  function performAIAnalysis(button, issueId) {
    if (!issueId) {
      alert("Invalid issue ID");
      return;
    }

    // Disable button and show loading state
    button.prop("disabled", true);
    var originalText = button.text();
    button.text("Analyzing...");

    // Perform AI analysis via AJAX
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_analyze_issue",
        issue_id: issueId,
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          // Show success message
          alert("AI analysis completed successfully!");
          // Reload the page to show updated analysis
          location.reload();
        } else {
          alert("Error: " + (response.data.message || "AI analysis failed"));
        }
      },
      error: function () {
        alert("Error performing AI analysis. Please try again.");
      },
      complete: function () {
        // Re-enable button and restore original text
        button.prop("disabled", false);
        button.text(originalText);
      },
    });
  }

  /**
   * Poll scan status and update progress with chunked processing
   *
   * @param {string} scanId - The scan ID to check (can be null for current scan)
   */
  function pollScanStatus(scanId) {
    // Clear any existing polling interval
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }

    // Start polling for scan status updates
    pollInterval = setInterval(function () {
      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_get_scan_status",
          scan_id: scanId,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          if (response.success && response.data) {
            var data = response.data;

            // Update progress based on current stage
            if (data.current_stage && data.progress !== undefined) {
              // Update stage progress
              stageProgress[data.current_stage] = parseInt(data.progress);

              // Calculate overall progress based on stage weights
              var totalProgress = 0;
              for (var stage in stageWeights) {
                if (stageProgress[stage] > 0) {
                  totalProgress +=
                    (stageProgress[stage] / 100) * stageWeights[stage];
                }
              }
              overallProgress = Math.round(totalProgress * 100);

              // Update progress bar and message
              updateProgressBar(
                overallProgress,
                data.current_stage,
                data.message || "Scanning in progress..."
              );
            }

            // Check if scan is complete
            if (
              data.status === "completed" ||
              data.status === "failed" ||
              data.status === "stopped"
            ) {
              // Stop polling
              clearInterval(pollInterval);
              pollInterval = null;

              // Update UI based on final status
              var statusArea = $("#scan-status-area");
              var startButton = $("#start-scan-button");
              var resumeButton = $("#resume-scan-button");
              var stopButton = $("#stop-scan-button");

              if (data.status === "completed") {
                updateProgressBar(
                  100,
                  "completed",
                  "Scan completed successfully!"
                );
                statusArea.html(
                  '<div class="notice notice-success"><p>Scan completed! Found ' +
                    (data.issues_found || 0) +
                    " security issues.</p></div>"
                );
              } else if (data.status === "failed") {
                statusArea.html(
                  '<div class="notice notice-error"><p>Scan failed: ' +
                    (data.error_message || "Unknown error") +
                    "</p></div>"
                );
              } else if (data.status === "stopped") {
                statusArea.html(
                  '<div class="notice notice-warning"><p>Scan was stopped by user.</p></div>'
                );
              }

              // Re-enable buttons
              startButton.prop("disabled", false).text("Start New Scan");
              if (resumeButton.length) {
                resumeButton.prop("disabled", false);
              }
              if (stopButton.length) {
                stopButton.prop("disabled", true);
              }
            } else if (data.status === "running") {
              // For chunked scans, trigger the next chunk processing
              processNextChunk();
            }
          } else {
            console.log("No scan status data received or scan not found");
          }
        },
        error: function (xhr) {
          console.log("Error polling scan status:", xhr.responseText);
          // Continue polling on error unless it's a 404 (scan not found)
          if (xhr.status === 404) {
            clearInterval(pollInterval);
            pollInterval = null;
          }
        },
      });
    }, 3000); // Poll every 3 seconds for chunked scans

    // Update global reference for stop scan functionality
    window.twssPollInterval = pollInterval;
  }

  /**
   * Process the next chunk of a chunked scan
   */
  function processNextChunk() {
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_process_scan_chunk",
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success && response.data) {
          var data = response.data;

          // Update progress
          if (data.stage && data.progress !== undefined) {
            stageProgress[data.stage] = parseInt(data.progress);

            // Calculate overall progress
            var totalProgress = 0;
            for (var stage in stageWeights) {
              if (stageProgress[stage] > 0) {
                totalProgress +=
                  (stageProgress[stage] / 100) * stageWeights[stage];
              }
            }
            overallProgress = Math.round(totalProgress * 100);

            updateProgressBar(
              overallProgress,
              data.stage,
              data.message || "Processing..."
            );
          }

          // If scan should continue, schedule next chunk
          if (data.continue) {
            setTimeout(processNextChunk, 1000); // Process next chunk after 1 second
          } else {
            // Scan completed, stop polling and update UI
            clearInterval(pollInterval);
            pollInterval = null;

            updateProgressBar(100, "completed", "Scan completed successfully!");
            $("#scan-status-area").html(
              '<div class="notice notice-success"><p>Scan completed! Processing results...</p></div>'
            );

            // Re-enable buttons
            $("#start-scan-button")
              .prop("disabled", false)
              .text("Start New Scan");
            $("#resume-scan-button").prop("disabled", false);
            $("#stop-scan-button").prop("disabled", true);
          }
        } else {
          console.error("Error processing scan chunk:", response.data);
        }
      },
      error: function (xhr) {
        console.error("AJAX error processing scan chunk:", xhr.responseText);
        // Don't stop the scan on chunk processing errors, continue polling
      },
    });
  }

  /**
   * Clean up ghost files from scan results
   */
  function cleanupGhostFiles() {
    if (
      confirm(
        "Clean up ghost files from scan results? This will remove entries for files that no longer exist on your WordPress instance."
      )
    ) {
      const button = $("#cleanup-ghost-files-button");
      const originalText = button.text();

      button.prop("disabled", true).text("Cleaning...");

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_cleanup_ghost_files",
          nonce: twss_data.nonce,
        },
        success: function (response) {
          button.prop("disabled", false).text(originalText);

          if (response.success) {
            // Show success message with count
            alert(response.data.message);

            // Reload page if ghost files were found and removed
            if (response.data.ghost_count > 0) {
              location.reload();
            }
          } else {
            alert("Error: " + (response.data.message || "Unknown error"));
          }
        },
        error: function () {
          button.prop("disabled", false).text(originalText);
          alert("Error cleaning up ghost files. Please try again.");
        },
      });
    }
  }

  // Test OpenRouter API Key
  $(document).on("click", "#test-openrouter-api", function (e) {
    e.preventDefault();
    var button = $(this);
    var apiKey = $("#twss_openrouter_api_key").val();
    var statusSpan = $("#openrouter-api-status");

    if (!apiKey) {
      statusSpan.html(
        '<span style="color: #d63638;">Please enter an API key first</span>'
      );
      return;
    }

    button.prop("disabled", true).text("Testing...");
    statusSpan.html(
      '<span style="color: #FF7342;">Testing connection...</span>'
    );

    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_test_openrouter_api",
        api_key: apiKey,
        nonce: twss_data.nonce,
      },
      success: function (response) {
        if (response.success) {
          statusSpan.html(
            '<span style="color: #46b450;">✓ ' +
              response.data.message +
              "</span>"
          );
        } else {
          statusSpan.html(
            '<span style="color: #d63638;">✗ ' +
              response.data.message +
              "</span>"
          );
        }
      },
      error: function () {
        statusSpan.html(
          '<span style="color: #d63638;">✗ Connection failed</span>'
        );
      },
      complete: function () {
        button.prop("disabled", false).text("Test API Key");
      },
    });
  });
})(jQuery);
