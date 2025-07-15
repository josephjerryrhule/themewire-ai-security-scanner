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
      ".fix-issue-button, .quarantine-button, .whitelist-button, .delete-button, .restore-core-button"
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
      // Open OAuth popup
      var popup = window.open(
        twss_data.admin_url +
          "admin.php?page=themewire-security-oauth&provider=" +
          provider,
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
   * Test API key
   *
   * @param {string} provider - The AI provider (openai or gemini)
   */
  function testApiKey(provider) {
    const button = $("#test-" + provider + "-api");
    const statusSpan = $("#" + provider + "-api-status");
    const apiKey = $("#twss_" + provider + "_api_key").val();

    if (!apiKey) {
      statusSpan.html(
        '<span style="color:red;">Please enter an API key first</span>'
      );
      return;
    }

    // Show loading
    button.prop("disabled", true);
    button.text(twss_data.i18n.testing || "Testing...");
    statusSpan.html(
      '<span class="loading-spinner" style="display:inline-block;"></span>'
    );

    // AJAX request to test API key
    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_test_" + provider + "_api",
        nonce: twss_data.nonce,
        api_key: apiKey,
      },
      success: function (response) {
        button.prop("disabled", false);
        button.text(twss_data.i18n.test_connection || "Test Connection");

        if (response.success) {
          statusSpan.html(
            '<span style="color:green;">' + response.data.message + "</span>"
          );
        } else {
          statusSpan.html(
            '<span style="color:red;">Error: ' +
              (response.data.message || "Unknown error") +
              "</span>"
          );
        }
      },
      error: function () {
        button.prop("disabled", false);
        button.text(twss_data.i18n.test_connection || "Test Connection");
        statusSpan.html(
          '<span style="color:red;">Server error. Please try again.</span>'
        );
      },
    });
  }

  /**
   * Poll for scan status updates
   */
  function pollScanStatus(scanId, interval = 3000) {
    // Clear any existing poll
    if (pollInterval) {
      clearInterval(pollInterval);
    }

    const statusArea = $("#scan-status-area");
    const resultsArea = $("#scan-results-area");

    // Use interval for polling to prevent getting stuck if a single request fails
    pollInterval = setInterval(function () {
      // If scan ID is null (after timeout), try to get the current scan ID
      var scanIdToUse = scanId;
      if (!scanIdToUse && twss_data.has_interrupted_scan) {
        // This will use the current scan ID stored in options
        scanIdToUse = "current";
      }

      if (!scanIdToUse) {
        clearInterval(pollInterval);
        return;
      }

      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_get_scan_status",
          nonce: twss_data.nonce,
          scan_id: scanIdToUse,
        },
        success: function (response) {
          if (response.success) {
            const data = response.data;

            // Update progress information
            if (data.progress && data.progress.length > 0) {
              // Update latest stage progress
              for (var i = 0; i < data.progress.length; i++) {
                var progressItem = data.progress[i];
                stageProgress[progressItem.stage] = progressItem.progress / 100;
                currentStage = progressItem.stage;

                // Find most recent message for current stage
                var latestMessage = progressItem.message;
              }

              // Calculate and update overall progress
              overallProgress = calculateOverallProgress();
              updateProgressBar(overallProgress, currentStage, latestMessage);
            }

            // Show status message
            let statusHtml =
              '<div class="notice notice-info"><p>Scan status: <strong>' +
              data.status +
              "</strong></p></div>";
            statusArea.html(statusHtml);

            // If scan is completed
            if (data.status === "completed") {
              clearInterval(pollInterval);

              const button = $("#start-scan-button");
              button.prop("disabled", false);
              button.text(twss_data.i18n.start_scan || "Start Scan");

              const resumeButton = $("#resume-scan-button");
              if (resumeButton.length) {
                resumeButton.remove(); // Remove resume button as scan is now complete
              }

              // Update progress bar to 100%
              updateProgressBar(100, "ai_analysis", "Scan completed");

              resultsArea.html(
                '<div class="card">' +
                  '<h2 class="card-title">Scan Results</h2>' +
                  "<p>Scan completed successfully.</p>" +
                  "<p>Total issues found: <strong>" +
                  data.total_issues +
                  "</strong></p>" +
                  '<p><a href="' +
                  twss_data.admin_url +
                  'admin.php?page=themewire-security-issues" class="button button-primary">View Issues</a></p>' +
                  "</div>"
              );

              // Reload page after 2 seconds to refresh stats
              setTimeout(function () {
                window.location.reload();
              }, 2000);
            } else if (data.status === "failed") {
              clearInterval(pollInterval);

              const button = $("#start-scan-button");
              button.prop("disabled", false);
              button.text(twss_data.i18n.start_scan || "Start Scan");

              const resumeButton = $("#resume-scan-button");
              if (resumeButton.length) {
                resumeButton.prop("disabled", false);
                resumeButton.text(twss_data.i18n.resume_scan || "Resume Scan");
              }

              $("#scan-progress-container").hide();
              statusArea.html(
                '<div class="notice notice-error"><p>Scan failed: ' +
                  (data.error_message || "Unknown error") +
                  "</p></div>"
              );
            }
          } else {
            // Only show error if we repeatedly fail
            console.log(
              "Error polling scan status: " +
                (response.data ? response.data.message : "Unknown error")
            );
          }
        },
        error: function (xhr) {
          // Log error but keep polling
          console.log(
            "Error polling scan status (HTTP " +
              xhr.status +
              "): " +
              xhr.statusText
          );
        },
      });
    }, interval);
  }

  /**
   * Perform an action on an issue
   *
   * @param {jQuery} button - The button that was clicked
   * @param {string} action - The AJAX action to perform
   * @param {number} issueId - The issue ID
   * @param {string} loadingText - Text to show while loading
   * @param {string} originalText - Original button text
   * @param {object} extraData - Additional data to send
   */
  function performIssueAction(
    button,
    action,
    issueId,
    loadingText,
    originalText,
    extraData = {}
  ) {
    console.log("performIssueAction called");
    console.log("Action:", action);
    console.log("Issue ID:", issueId);
    console.log("TWSS Data available:", !!twss_data);
    console.log("AJAX URL:", twss_data ? twss_data.ajax_url : "undefined");
    console.log("Nonce:", twss_data ? twss_data.nonce : "undefined");

    // Validate inputs
    if (!twss_data || !twss_data.ajax_url || !twss_data.nonce) {
      console.error("TWSS data not available:", twss_data);
      alert("Error: Plugin data not loaded properly. Please refresh the page.");
      return;
    }

    if (!issueId) {
      console.error("No issue ID provided");
      alert("Error: No issue ID provided.");
      return;
    }

    button.prop("disabled", true);
    button.text(loadingText);

    const data = {
      action: action,
      nonce: twss_data.nonce,
      issue_id: issueId,
      ...extraData,
    };

    console.log("Sending AJAX request with data:", data);
    console.log("Full AJAX URL:", twss_data.ajax_url);

    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: data,
      timeout: 30000, // 30 second timeout
      beforeSend: function (xhr) {
        console.log("AJAX request starting...");
        console.log("Request headers:", xhr.getAllResponseHeaders());
      },
      success: function (response, textStatus, xhr) {
        console.log("AJAX response received:");
        console.log("Status:", textStatus);
        console.log("Response:", response);
        console.log("Response type:", typeof response);

        // Handle both JSON and string responses
        let parsedResponse = response;
        if (typeof response === "string") {
          try {
            parsedResponse = JSON.parse(response);
          } catch (e) {
            console.error("Failed to parse response as JSON:", response);
            alert("Error: Invalid response from server. Response: " + response);
            button.prop("disabled", false);
            button.text(originalText);
            return;
          }
        }

        console.log("Parsed response:", parsedResponse);

        if (parsedResponse && parsedResponse.success) {
          // Show success message
          var successMessage =
            parsedResponse.data && parsedResponse.data.message
              ? parsedResponse.data.message
              : "Action completed successfully";

          console.log("Action successful:", successMessage);

          // Create a temporary success notice
          var notice = $(
            '<div class="notice notice-success is-dismissible"><p>' +
              successMessage +
              "</p></div>"
          );
          $(".themewire-security-wrap h1").after(notice);

          // Remove the table row with animation
          button.closest("tr").fadeOut(500, function () {
            $(this).remove();

            // Check if table is empty
            const tbody = $(".wp-list-table tbody");
            if (tbody.children().length === 0) {
              setTimeout(function () {
                location.reload(); // Reload to show "no issues" message
              }, 1000);
            }
          });
        } else {
          console.error("Action failed:", parsedResponse);
          var errorMessage =
            parsedResponse && parsedResponse.data && parsedResponse.data.message
              ? parsedResponse.data.message
              : parsedResponse && parsedResponse.message
              ? parsedResponse.message
              : "Unknown error occurred";

          alert("Error: " + errorMessage);
          button.prop("disabled", false);
          button.text(originalText);
        }
      },
      error: function (xhr, status, error) {
        console.error("AJAX error occurred:");
        console.error("Status:", status);
        console.error("Error:", error);
        console.error("Response Text:", xhr.responseText);
        console.error("Status Code:", xhr.status);
        console.error("Ready State:", xhr.readyState);

        var errorMessage = "Server error occurred.";

        // Check for specific HTTP error codes
        switch (xhr.status) {
          case 403:
            errorMessage =
              "Permission denied. Please refresh the page and try again.";
            break;
          case 404:
            errorMessage =
              "AJAX endpoint not found. Please check plugin installation.";
            break;
          case 500:
            errorMessage = "Internal server error. Check error logs.";
            break;
          case 0:
            errorMessage = "Network error. Please check your connection.";
            break;
          default:
            if (xhr.responseText) {
              errorMessage =
                "Server error: " + xhr.responseText.substring(0, 100);
            }
        }

        // Check if response contains HTML (indicating an error page)
        if (xhr.responseText && xhr.responseText.includes("<!DOCTYPE")) {
          errorMessage =
            "Server returned an error page. Check WordPress error logs.";
        }

        alert(errorMessage + " Check browser console for details.");
        button.prop("disabled", false);
        button.text(originalText);
      },
    });
  }
})(jQuery);
