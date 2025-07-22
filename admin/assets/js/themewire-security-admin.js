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
      if (typeof window.stopScan === 'function') {
        window.stopScan();
      }
    });

    // Handle Clear All Issues button click (uses global function from additional.js)
    $("#clear-all-issues-button").on("click", function () {
      console.log("Clear all issues button clicked");
      if (typeof window.clearAllIssues === 'function') {
        window.clearAllIssues();
      }
    });

    // Handle Clear Scan Issues button click (uses global function from additional.js)
    $(document).on("click", ".clear-scan-issues-button", function () {
      var scanId = $(this).data("scan-id");
      console.log("Clear scan issues button clicked for scan:", scanId);
      if (typeof window.clearScanIssues === 'function') {
        window.clearScanIssues(scanId);
      }
    });

    // AI Connection Testing
    setupAIConnectionTesting();

    // OAuth Flow Handlers
    setupOAuthHandlers();

    // Bulk Actions for Scan Results
    setupBulkActions();

    // Enhanced Filtering for Issues Page
    setupIssuesFiltering();
  });

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
      const button = $(".clear-scan-issues-button[data-scan-id='" + scanId + "']");
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
      const button = $(".clear-scan-issues-button[data-scan-id='" + scanId + "']");
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
      const button = $(".clear-scan-issues-button[data-scan-id='" + scanId + "']");
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

      if (confirm("Are you sure you want to " + action + " the selected files?")) {
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
      alert('Invalid issue ID');
      return;
    }

    // Disable button and show loading state
    button.prop('disabled', true);
    var originalText = button.text();
    button.text('Analyzing...');

    // Perform AI analysis via AJAX
    $.ajax({
      url: twss_data.ajax_url,
      type: 'POST',
      data: {
        action: 'twss_analyze_issue',
        issue_id: issueId,
        nonce: twss_data.nonce
      },
      success: function(response) {
        if (response.success) {
          // Show success message
          alert('AI analysis completed successfully!');
          // Reload the page to show updated analysis
          location.reload();
        } else {
          alert('Error: ' + (response.data.message || 'AI analysis failed'));
        }
      },
      error: function() {
        alert('Error performing AI analysis. Please try again.');
      },
      complete: function() {
        // Re-enable button and restore original text
        button.prop('disabled', false);
        button.text(originalText);
      }
    });
  }
})(jQuery);
