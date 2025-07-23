#!/usr/bin/env python3
import re

# Read the file
with open('/Users/joeseph/Desktop/Dev/public/kwameamfo/wp-content/plugins/themewire-ai-security-scanner/admin/assets/js/themewire-security-admin.js', 'r') as f:
    content = f.read()

# Fix broken HTML generation
content = content.replace('<div class="scan-stage-item " + status + "', '<div class="scan-stage-item " + status + "\">')
content = content.replace('+ status + "\">', '+ status + "\"">')

# Fix the broken case statement formatting
content = content.replace('break;      default:', 'break;\n      default:')

# Write back
with open('/Users/joeseph/Desktop/Dev/public/kwameamfo/wp-content/plugins/themewire-ai-security-scanner/admin/assets/js/themewire-security-admin.js', 'w') as f:
    f.write(content)

print('Fixed JavaScript formatting issues')
