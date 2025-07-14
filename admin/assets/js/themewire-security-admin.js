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
    // Handle Start Scan button click
    $("#start-scan-button").on("click", function () {
      startScan();
    });

    // Handle Resume Scan button click
    $("#resume-scan-button").on("click", function () {
      resumeScan();
    });

    // Handle OpenAI API test button
    $("#test-openai-api").on("click", function () {
      testApiKey("openai");
    });

    // Handle Gemini API test button
    $("#test-gemini-api").on("click", function () {
      testApiKey("gemini");
    });

    // Handle issue fix buttons
    $(".fix-issue-button").on("click", function () {
      const button = $(this);
      const issueId = button.data("issue-id");

      if (confirm("Are you sure you want to fix this issue?")) {
        button.prop("disabled", true);
        button.text("Fixing...");

        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_fix_issue",
            nonce: twss_data.nonce,
            issue_id: issueId,
          },
          success: function (response) {
            if (response.success) {
              button.closest("tr").fadeOut(500, function () {
                $(this).remove();
              });
            } else {
              alert("Error: " + (response.data.message || "Unknown error"));
              button.prop("disabled", false);
              button.text("Fix");
            }
          },
          error: function () {
            alert("Server error. Please try again.");
            button.prop("disabled", false);
            button.text("Fix");
          },
        });
      }
    });

    // Other event handlers remain the same
    // ...
  });

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
})(jQuery);
