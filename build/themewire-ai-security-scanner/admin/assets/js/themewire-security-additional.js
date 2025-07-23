/**
 * Additional JavaScript functions for stop scan and clear issues functionality
 * This should be appended to the main themewire-security-admin.js file
 */

(function ($) {
  "use strict";

  /**
   * Stop the current scan
   */
  function stopScan() {
    const button = $("#stop-scan-button");
    const startButton = $("#start-scan-button");
    const resumeButton = $("#resume-scan-button");
    const statusArea = $("#scan-status-area");

    if (confirm("Are you sure you want to stop the current scan?")) {
      // Disable stop button and show loading
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
          if (response.success) {
            // Stop polling
            if (window.twssPollInterval) {
              clearInterval(window.twssPollInterval);
              window.twssPollInterval = null;
            }

            // Reset buttons
            button.prop("disabled", false);
            button.text("Stop Scan");
            button.hide(); // Hide stop button when no scan is running

            startButton.prop("disabled", false);
            startButton.text("Start New Scan");
            startButton.show();

            if (resumeButton.length) {
              resumeButton.prop("disabled", false);
              resumeButton.hide();
            }

            // Hide progress container and show success message
            $("#scan-progress-container").hide();
            statusArea.html(
              '<div class="notice notice-warning"><p>' +
                response.data.message +
                "</p></div>"
            );

            setTimeout(function () {
              statusArea.html("");
            }, 5000);
          } else {
            button.prop("disabled", false);
            button.text("Stop Scan");

            statusArea.html(
              '<div class="notice notice-error"><p>Error stopping scan: ' +
                (response.data.message || "Unknown error") +
                "</p></div>"
            );
          }
        },
        error: function () {
          button.prop("disabled", false);
          button.text("Stop Scan");

          statusArea.html(
            '<div class="notice notice-error"><p>Error stopping scan. Please try again.</p></div>'
          );
        },
      });
    }
  }

  /**
   * Clear all issues from database
   */
  function clearAllIssues() {
    if (
      confirm(
        "Are you sure you want to clear ALL issues and scan history? This action cannot be undone."
      )
    ) {
      const button = $("#clear-all-issues-button");

      // Disable button and show loading
      button.prop("disabled", true);
      button.text("Clearing...");

      // AJAX request to clear all issues
      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_all_issues",
          nonce: twss_data.nonce,
        },
        success: function (response) {
          button.prop("disabled", false);
          button.text("Clear All Issues");

          if (response.success) {
            // Reset scan buttons immediately
            const startButton = $("#start-scan-button");
            const resumeButton = $("#resume-scan-button");
            const stopButton = $("#stop-scan-button");

            if (startButton.length) {
              startButton.prop("disabled", false);
              startButton.text("Start New Scan");
              startButton.show();
            }

            if (resumeButton.length) {
              resumeButton.hide();
            }

            if (stopButton.length) {
              stopButton.hide();
            }

            // Show success message
            const statusArea = $("#scan-status-area");
            if (statusArea.length) {
              statusArea.html(
                '<div class="notice notice-success"><p>' +
                  response.data.message +
                  "</p></div>"
              );
            } else {
              alert(response.data.message);
            }

            // Reload the page to refresh the issues list
            setTimeout(function () {
              location.reload();
            }, 2000);
          } else {
            alert("Error: " + (response.data.message || "Unknown error"));
          }
        },
        error: function () {
          button.prop("disabled", false);
          button.text("Clear All Issues");
          alert("Error clearing issues. Please try again.");
        },
      });
    }
  }

  /**
   * Clear issues from a specific scan
   */
  function clearScanIssues(scanId) {
    if (confirm("Are you sure you want to clear all issues from this scan?")) {
      const button = $(
        ".clear-scan-issues-button[data-scan-id='" + scanId + "']"
      );

      // Disable button and show loading
      button.prop("disabled", true);
      button.text("Clearing...");

      // AJAX request to clear scan issues
      $.ajax({
        url: twss_data.ajax_url,
        type: "POST",
        data: {
          action: "twss_clear_scan_issues",
          scan_id: scanId,
          nonce: twss_data.nonce,
        },
        success: function (response) {
          button.prop("disabled", false);
          button.text("Clear Issues");

          if (response.success) {
            // Show success message
            const statusArea = $("#scan-status-area");
            if (statusArea.length) {
              statusArea.html(
                '<div class="notice notice-success"><p>' +
                  response.data.message +
                  "</p></div>"
              );
            } else {
              alert(response.data.message);
            }

            // Reload the page to refresh the issues list
            setTimeout(function () {
              location.reload();
            }, 2000);
          } else {
            alert("Error: " + (response.data.message || "Unknown error"));
          }
        },
        error: function () {
          button.prop("disabled", false);
          button.text("Clear Issues");
          alert("Error clearing scan issues. Please try again.");
        },
      });
    }
  }

  // Add event handlers when document is ready
  $(document).ready(function () {
    // Handle Stop Scan button click
    $(document).on("click", "#stop-scan-button", function () {
      console.log("Stop scan button clicked");
      stopScan();
    });

    // Handle Clear All Issues button click
    $(document).on("click", "#clear-all-issues-button", function () {
      console.log("Clear all issues button clicked");
      clearAllIssues();
    });

    // Handle Clear Scan Issues button click (for specific scans)
    $(document).on("click", ".clear-scan-issues-button", function () {
      var scanId = $(this).data("scan-id");
      console.log("Clear scan issues button clicked for scan:", scanId);
      clearScanIssues(scanId);
    });
  });

  // Make functions globally available for the main JS file
  window.stopScan = stopScan;
  window.clearAllIssues = clearAllIssues;
  window.clearScanIssues = clearScanIssues;
})(jQuery);
