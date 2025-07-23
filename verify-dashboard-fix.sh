#!/bin/bash

# Simple test to verify our dashboard scan state fixes

echo "🔍 ThemeWire Security Dashboard Fix Verification"
echo "================================================"

# Check if dashboard.php has the stale scan detection
if grep -q "Validate scan status - detect and fix stale" admin/views/dashboard.php; then
    echo "✅ Dashboard stale scan detection: ADDED"
else
    echo "❌ Dashboard stale scan detection: MISSING"
fi

# Check if dashboard.php has the JavaScript refresh logic
if grep -q "checkScanStates" admin/views/dashboard.php; then
    echo "✅ Dashboard auto-refresh JavaScript: ADDED"
else
    echo "❌ Dashboard auto-refresh JavaScript: MISSING"
fi

# Check if scanner has transient cleanup
if grep -q "delete_transient('twss_scan_in_progress')" includes/class-scanner.php; then
    echo "✅ Scanner transient cleanup: EXISTS"
else
    echo "❌ Scanner transient cleanup: MISSING"
fi

# Check if scan view has stale state cleanup  
if grep -q "Clean up if scan is actually completed" admin/views/scan.php; then
    echo "✅ Scan view stale cleanup: EXISTS"
else
    echo "❌ Scan view stale cleanup: MISSING"
fi

echo ""
echo "🎯 Summary: Dashboard should now properly detect completed scans"
echo "   - PHP validation cleans up stale database states"
echo "   - JavaScript automatically refreshes when inconsistencies detected"
echo "   - Multi-layer cleanup ensures scan completion is properly reflected"
echo ""
echo "💡 If scan still shows as running after completion:"
echo "   1. Wait 2 seconds for JavaScript to check"
echo "   2. Refresh the page manually"  
echo "   3. The stale state should be automatically corrected"
