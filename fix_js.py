#!/usr/bin/env python3
import re

# Read the file
with open('/Users/joeseph/Desktop/Dev/public/kwameamfo/wp-content/plugins/themewire-ai-security-scanner/admin/assets/js/themewire-security-admin.js', 'r') as f:
    content = f.read()

# Pattern to find the stage status logic to replace - being more specific
pattern1 = r'for \(var i = 0; i < stages\.length; i\+\+\) \{\s*var status = "pending";\s*var statusText = "Pending";\s*\s*// Set stage status\s*if \(stages\[i\] === stage\) \{\s*status = "in-progress";\s*statusText = "In Progress";\s*\} else if \(stages\.indexOf\(stage\) > stages\.indexOf\(stages\[i\]\)\) \{\s*status = "completed";\s*statusText = "Completed";\s*\}'

replacement1 = '''for (var i = 0; i < stages.length; i++) {
      var status = "pending";
      var statusText = "Pending";

      // If scan is completed, mark all stages as completed
      var isCompleted = (stage === "completed" || percent >= 100);

      // Set stage status based on completion
      if (isCompleted) {
        status = "completed";
        statusText = "Completed";
      } else if (stages[i] === stage) {
        status = "in-progress";
        statusText = "In Progress";
      } else if (stages.indexOf(stage) > stages.indexOf(stages[i])) {
        status = "completed";
        statusText = "Completed";
      }'''

# Apply the replacement with MULTILINE and DOTALL flags
content = re.sub(pattern1, replacement1, content, flags=re.MULTILINE | re.DOTALL)

# Also fix CSS class names to match our CSS
content = content.replace('<span class="stage-name">', '<span class="scan-stage-title">')
content = content.replace('<span class="stage-status ', '<span class="scan-stage-status">')
content = content.replace('<div class="scan-stage-item">', '<div class="scan-stage-item ')
content = content.replace('<div class="scan-stage-item ', '<div class="scan-stage-item " + status + "')

# Write back
with open('/Users/joeseph/Desktop/Dev/public/kwameamfo/wp-content/plugins/themewire-ai-security-scanner/admin/assets/js/themewire-security-admin.js', 'w') as f:
    f.write(content)

print('Updated JavaScript file with scan completion fixes')
