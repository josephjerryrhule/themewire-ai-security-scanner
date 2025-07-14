/**
 * Admin JavaScript for Themewire AI Security Scanner
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

(function ($) {
  "use strict";

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

    // Handle quarantine buttons
    $(".quarantine-button").on("click", function () {
      const button = $(this);
      const issueId = button.data("issue-id");

      if (confirm("Are you sure you want to quarantine this file?")) {
        button.prop("disabled", true);
        button.text("Quarantining...");

        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_quarantine_file",
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
              button.text("Quarantine");
            }
          },
          error: function () {
            alert("Server error. Please try again.");
            button.prop("disabled", false);
            button.text("Quarantine");
          },
        });
      }
    });

    // Handle whitelist buttons
    $(".whitelist-button").on("click", function () {
      const button = $(this);
      const issueId = button.data("issue-id");
      const reason = prompt("Why are you whitelisting this file?");

      if (reason !== null) {
        button.prop("disabled", true);
        button.text("Whitelisting...");

        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_whitelist_file",
            nonce: twss_data.nonce,
            issue_id: issueId,
            reason: reason,
          },
          success: function (response) {
            if (response.success) {
              button.closest("tr").fadeOut(500, function () {
                $(this).remove();
              });
            } else {
              alert("Error: " + (response.data.message || "Unknown error"));
              button.prop("disabled", false);
              button.text("Whitelist");
            }
          },
          error: function () {
            alert("Server error. Please try again.");
            button.prop("disabled", false);
            button.text("Whitelist");
          },
        });
      }
    });

    // Handle delete buttons
    $(".delete-button").on("click", function () {
      const button = $(this);
      const issueId = button.data("issue-id");

      if (
        confirm(
          "WARNING: Are you sure you want to delete this file? This action cannot be undone."
        )
      ) {
        button.prop("disabled", true);
        button.text("Deleting...");

        $.ajax({
          url: twss_data.ajax_url,
          type: "POST",
          data: {
            action: "twss_delete_file",
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
              button.text("Delete");
            }
          },
          error: function () {
            alert("Server error. Please try again.");
            button.prop("disabled", false);
            button.text("Delete");
          },
        });
      }
    });
  });

  /**
   * Start a new scan
   */
  function startScan() {
    const button = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

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
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
          }

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
        } else {
          button.prop("disabled", false);
          button.text(twss_data.i18n.resume_scan || "Resume Scan");
          startButton.prop("disabled", false);

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
    const statusArea = $("#scan-status-area");
    const resultsArea = $("#scan-results-area");

    $.ajax({
      url: twss_data.ajax_url,
      type: "POST",
      data: {
        action: "twss_get_scan_status",
        nonce: twss_data.nonce,
        scan_id: scanId,
      },
      success: function (response) {
        if (response.success) {
          const data = response.data;
          let statusHtml =
            '<div class="card"><h2 class="card-title">Scan Progress</h2>';

          // Show progress for each stage
          if (data.progress && data.progress.length > 0) {
            statusHtml += "<ul>";
            for (let i = 0; i < data.progress.length; i++) {
              statusHtml +=
                "<li><strong>" +
                data.progress[i].stage +
                ":</strong> " +
                data.progress[i].message +
                "</li>";
            }
            statusHtml += "</ul>";
          }

          statusHtml += "<p>Status: <strong>" + data.status + "</strong></p>";
          statusHtml += "</div>";

          statusArea.html(statusHtml);

          // If scan is completed
          if (data.status === "completed") {
            const button = $("#start-scan-button");
            button.prop("disabled", false);
            button.text(twss_data.i18n.start_scan || "Start Scan");

            const resumeButton = $("#resume-scan-button");
            if (resumeButton.length) {
              resumeButton.remove(); // Remove resume button as scan is now complete
            }

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
            const button = $("#start-scan-button");
            button.prop("disabled", false);
            button.text(twss_data.i18n.start_scan || "Start Scan");

            const resumeButton = $("#resume-scan-button");
            if (resumeButton.length) {
              resumeButton.prop("disabled", false);
              resumeButton.text(twss_data.i18n.resume_scan || "Resume Scan");
            }

            statusArea.html(
              '<div class="notice notice-error"><p>Scan failed: ' +
                (data.error_message || "Unknown error") +
                "</p></div>"
            );
          } else {
            // Continue polling if scan is still in progress
            setTimeout(function () {
              pollScanStatus(scanId, interval);
            }, interval);
          }
        } else {
          statusArea.html(
            '<div class="notice notice-error"><p>Error: ' +
              (response.data.message || "Unknown error") +
              "</p></div>"
          );
          const button = $("#start-scan-button");
          button.prop("disabled", false);
          button.text(twss_data.i18n.start_scan || "Start Scan");

          const resumeButton = $("#resume-scan-button");
          if (resumeButton.length) {
            resumeButton.prop("disabled", false);
            resumeButton.text(twss_data.i18n.resume_scan || "Resume Scan");
          }
        }
      },
      error: function () {
        statusArea.html(
          '<div class="notice notice-error"><p>Server error. Retrying...</p></div>'
        );

        // Retry after a slightly longer interval
        setTimeout(function () {
          pollScanStatus(scanId, interval * 1.5);
        }, interval * 1.5);
      },
    });
  }
})(jQuery);
