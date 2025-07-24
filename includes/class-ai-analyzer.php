<?php

/**
 * AI analysis functionality for the plugin.
 *
 * @link       https://themewire.com
 * @since      1.0.0
 *
 * @package    Themewire_Security
 */

class Themewire_Security_AI_Analyzer
{

    /**
     * OpenAI API client.
     *
     * @since    1.0.0
     * @access   private
     * @var      object    $openai_client
     */
    private $openai_client = null;

    /**
     * Gemini API client.
     *
     * @since    1.0.0
     * @access   private
     * @var      object    $gemini_client
     */
    private $gemini_client = null;

    /**
     * OpenRouter API client.
     *
     * @since    1.0.27
     * @access   private
     * @var      object    $openrouter_client
     */
    private $openrouter_client = null;

    /**
     * Groq API client.
     *
     * @since    1.0.31
     * @access   private
     * @var      object    $groq_client
     */
    private $groq_client = null;

    /**
     * Files queued for AI analysis.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $queued_files
     */
    private $queued_files = array();

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     */
    public function __construct()
    {
        // Load API client libraries if needed
        $this->init_ai_clients();
    }

    /**
     * Initialize AI API clients with enhanced security validation
     *
     * @since    1.0.32
     * @security Enhanced API key validation and sanitization
     */
    private function init_ai_clients()
    {
        // Check if WordPress functions are available
        if (!function_exists('sanitize_text_field') || !function_exists('get_option')) {
            return; // Skip initialization if WordPress not loaded
        }

        $ai_provider = sanitize_text_field(get_option('twss_ai_provider', 'openai'));

        // Security: Validate provider whitelist
        $allowed_providers = array('openai', 'gemini', 'openrouter', 'groq');
        if (!in_array($ai_provider, $allowed_providers, true)) {
            error_log('TWSS Security: Invalid AI provider detected: ' . $ai_provider);
            return;
        }

        switch ($ai_provider) {
            case 'openai':
                $api_key = $this->sanitize_api_key(get_option('twss_openai_api_key', ''));
                if ($this->validate_api_key_format($api_key, 'openai')) {
                    $this->init_openai_client($api_key);
                }
                break;

            case 'gemini':
                $api_key = $this->sanitize_api_key(get_option('twss_gemini_api_key', ''));
                if ($this->validate_api_key_format($api_key, 'gemini')) {
                    $this->init_gemini_client($api_key);
                }
                break;

            case 'openrouter':
                $api_key = $this->sanitize_api_key(get_option('twss_openrouter_api_key', ''));
                if ($this->validate_api_key_format($api_key, 'openrouter')) {
                    $this->init_openrouter_client($api_key);
                }
                break;

            case 'groq':
                $api_key = $this->sanitize_api_key(get_option('twss_groq_api_key', ''));
                if ($this->validate_api_key_format($api_key, 'groq')) {
                    $this->init_groq_client($api_key);
                }
                break;
        }
    }

    /**
     * Sanitize API key input
     *
     * @since    1.0.32
     * @param    string    $api_key    Raw API key
     * @return   string    Sanitized API key
     * @security Prevent injection attacks via API keys
     */
    private function sanitize_api_key($api_key)
    {
        // Remove any potentially dangerous characters
        $api_key = preg_replace('/[^a-zA-Z0-9\-_]/', '', $api_key);

        // Limit length to reasonable bounds
        $api_key = substr($api_key, 0, 200);

        return $api_key;
    }

    /**
     * Validate API key format for security
     *
     * @since    1.0.32
     * @param    string    $api_key     API key to validate
     * @param    string    $provider    Provider name
     * @return   boolean   True if valid format
     * @security Prevent malformed API keys from being used
     */
    private function validate_api_key_format($api_key, $provider)
    {
        if (empty($api_key)) {
            return false;
        }

        $patterns = array(
            'openai' => '/^sk-[a-zA-Z0-9]{48,}$/',
            'gemini' => '/^[a-zA-Z0-9_-]{39}$/',
            'openrouter' => '/^sk-or-[a-zA-Z0-9_-]{43}$/',
            'groq' => '/^gsk_[a-zA-Z0-9]{52}$/'
        );

        if (!isset($patterns[$provider])) {
            return false;
        }

        return preg_match($patterns[$provider], $api_key) === 1;
    }

    /**
     * Initialize OpenAI API client
     *
     * @since    1.0.0
     * @param    string    $api_key    OpenAI API key
     */
    private function init_openai_client($api_key)
    {
        // Simple implementation - in production you might use a proper SDK
        $this->openai_client = new stdClass();
        $this->openai_client->api_key = $api_key;
    }

    /**
     * Initialize Gemini API client
     *
     * @since    1.0.0
     * @param    string    $api_key    Gemini API key
     */
    private function init_gemini_client($api_key)
    {
        // Simple implementation - in production you might use a proper SDK
        $this->gemini_client = new stdClass();
        $this->gemini_client->api_key = $api_key;
    }

    /**
     * Initialize OpenRouter API client
     *
     * @since    1.0.27
     * @param    string    $api_key    OpenRouter API key
     */
    private function init_openrouter_client($api_key)
    {
        // Initialize OpenRouter client
        $this->openrouter_client = new stdClass();
        $this->openrouter_client->api_key = $api_key;
    }

    /**
     * Initialize Groq API client
     *
     * @since    1.0.31
     * @param    string    $api_key    Groq API key
     */
    private function init_groq_client($api_key)
    {
        // Initialize Groq client
        $this->groq_client = new stdClass();
        $this->groq_client->api_key = $api_key;
    }

    /**
     * Queue a file for AI analysis with enhanced security validation
     *
     * @since    1.0.32
     * @param    int       $scan_id    The scan ID
     * @param    string    $file_path  Path to the file
     * @return   boolean   True on success, false on failure
     * @security Enhanced path validation and file type checking
     */
    public function queue_file_for_analysis($scan_id, $file_path)
    {
        // Security: Validate scan ID is positive integer
        if (!is_int($scan_id) || $scan_id <= 0) {
            error_log('TWSS Security: Invalid scan ID provided: ' . var_export($scan_id, true));
            return false;
        }

        // Security: Validate and sanitize file path
        $file_path = $this->validate_and_sanitize_file_path($file_path);
        if ($file_path === false) {
            return false;
        }

        // Security: Check file exists, is readable, and within allowed bounds
        if (!$this->is_safe_file_for_analysis($file_path)) {
            return false;
        }

        // Initialize scan queue if needed
        if (!isset($this->queued_files[$scan_id])) {
            $this->queued_files[$scan_id] = array();
        }

        // Security: Prevent queue overflow (max 1000 files per scan)
        if (count($this->queued_files[$scan_id]) >= 1000) {
            error_log('TWSS Security: Queue limit reached for scan ID: ' . $scan_id);
            return false;
        }

        $this->queued_files[$scan_id][] = $file_path;
        return true;
    }

    /**
     * Validate and sanitize file path for security
     *
     * @since    1.0.32
     * @param    string    $file_path    Raw file path
     * @return   string|false    Sanitized path or false if invalid
     * @security Prevent path traversal and injection attacks
     */
    private function validate_and_sanitize_file_path($file_path)
    {
        // Basic type and length validation
        if (!is_string($file_path) || strlen($file_path) > 500) {
            error_log('TWSS Security: Invalid file path type or length');
            return false;
        }

        // Security: Prevent path traversal attacks
        if (strpos($file_path, '..') !== false) {
            error_log('TWSS Security: Path traversal attempt blocked: ' . $file_path);
            return false;
        }

        // Security: Ensure path is absolute and within WordPress directory
        $wp_root = rtrim(ABSPATH, '/');
        $real_path = realpath($file_path);

        if ($real_path === false || strpos($real_path, $wp_root) !== 0) {
            error_log('TWSS Security: File outside WordPress directory blocked: ' . $file_path);
            return false;
        }

        return $real_path;
    }

    /**
     * Check if file is safe for analysis
     *
     * @since    1.0.32
     * @param    string    $file_path    File path to check
     * @return   boolean   True if safe for analysis
     * @security Enhanced file safety validation
     */
    private function is_safe_file_for_analysis($file_path)
    {
        // Check basic file properties
        if (!file_exists($file_path) || !is_readable($file_path) || !is_file($file_path)) {
            return false;
        }

        // Security: Check file size limits (max 10MB for analysis)
        $file_size = filesize($file_path);
        if ($file_size === false || $file_size > 10485760) { // 10MB
            error_log('TWSS Security: File too large for analysis: ' . $file_path . ' (' . $file_size . ' bytes)');
            return false;
        }

        // Security: Validate file extension
        $allowed_extensions = array('php', 'js', 'html', 'htm', 'css', 'sql', 'txt', 'htaccess');
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));

        if (!in_array($extension, $allowed_extensions, true)) {
            // Allow files without extensions (common for malware)
            if ($extension !== '') {
                return false;
            }
        }

        // Security: Basic binary file detection
        if ($this->is_likely_binary_file($file_path)) {
            return false;
        }

        return true;
    }

    /**
     * Detect if file is likely binary (not suitable for text analysis)
     *
     * @since    1.0.32
     * @param    string    $file_path    File path to check
     * @return   boolean   True if likely binary
     * @security Prevent analysis of binary files that could cause issues
     */
    private function is_likely_binary_file($file_path)
    {
        // Read first 1024 bytes to check for binary content
        $handle = fopen($file_path, 'rb');
        if ($handle === false) {
            return true; // If we can't read it, treat as binary
        }

        $chunk = fread($handle, 1024);
        fclose($handle);

        if ($chunk === false) {
            return true;
        }

        // Check for null bytes (common in binary files)
        if (strpos($chunk, "\0") !== false) {
            return true;
        }

        // Check for high ratio of non-printable characters
        $printable = 0;
        $total = strlen($chunk);

        for ($i = 0; $i < $total; $i++) {
            $ascii = ord($chunk[$i]);
            // Count printable ASCII characters and common whitespace
            if (($ascii >= 32 && $ascii <= 126) || in_array($ascii, array(9, 10, 13))) {
                $printable++;
            }
        }

        // If less than 70% printable characters, likely binary
        return ($printable / $total) < 0.7;
    }

    /**
     * Get files queued for analysis
     *
     * @since    1.0.0
     * @param    int       $scan_id    The scan ID
     * @return   array     Array of file paths
     */
    public function get_queued_files($scan_id)
    {
        return isset($this->queued_files[$scan_id]) ? $this->queued_files[$scan_id] : array();
    }

    /**
     * Analyze a file using AI with enhanced security validation
     *
     * @since    1.0.32
     * @param    string    $file_path    Path to the file
     * @return   array     Analysis result with security enhancements
     * @security Enhanced file validation and content sanitization
     */
    public function analyze_file($file_path)
    {
        // Security: Validate and sanitize file path
        $file_path = $this->validate_and_sanitize_file_path($file_path);
        if ($file_path === false) {
            return array(
                'is_malicious' => false,
                'confidence' => 0,
                'indicators' => array(),
                'error' => 'Invalid or unsafe file path'
            );
        }

        // Security: Enhanced file safety check
        if (!$this->is_safe_file_for_analysis($file_path)) {
            return array(
                'is_malicious' => false,
                'confidence' => 0,
                'indicators' => array(),
                'error' => 'File not suitable for analysis'
            );
        }

        // Security: Read file content with size limits and validation
        $file_content = $this->safely_read_file_content($file_path);
        if ($file_content === false) {
            return array(
                'is_malicious' => false,
                'confidence' => 0,
                'indicators' => array(),
                'error' => 'Failed to safely read file content'
            );
        }

        $file_extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));

        // Security: Limit file content to prevent API abuse and resource exhaustion
        $file_content = $this->truncate_file_content($file_content, 8000); // Reduced for security

        // Check if WordPress functions are available for getting AI provider
        if (function_exists('sanitize_text_field') && function_exists('get_option')) {
            $ai_provider = sanitize_text_field(get_option('twss_ai_provider', 'openai'));
        } else {
            $ai_provider = 'openai'; // Default fallback
        }

        // Use appropriate AI provider with fallback to secure pattern analysis
        try {
            switch ($ai_provider) {
                case 'openai':
                    if ($this->openai_client) {
                        return $this->analyze_with_openai($file_path, $file_content, $file_extension);
                    }
                    break;

                case 'gemini':
                    if ($this->gemini_client) {
                        return $this->analyze_with_gemini($file_path, $file_content, $file_extension);
                    }
                    break;

                case 'openrouter':
                    if ($this->openrouter_client) {
                        return $this->analyze_with_openrouter($file_path, $file_content, $file_extension);
                    }
                    break;

                case 'groq':
                    if ($this->groq_client) {
                        return $this->analyze_with_groq($file_path, $file_content, $file_extension);
                    }
                    break;
            }
        } catch (Exception $e) {
            // Log error securely without exposing sensitive information
            error_log('TWSS AI Analysis Error: ' . $e->getMessage());
        }

        // Always fallback to secure pattern-based analysis
        return $this->analyze_with_fallback($file_path, $file_content, $file_extension);
    }

    /**
     * Safely read file content with security constraints
     *
     * @since    1.0.32
     * @param    string    $file_path    File path to read
     * @return   string|false    File content or false on failure
     * @security Memory-safe file reading with limits
     */
    private function safely_read_file_content($file_path)
    {
        // Security: Double-check file existence and readability
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        // Security: Check available memory before reading
        $file_size = filesize($file_path);
        if ($file_size === false) {
            return false;
        }

        $memory_limit = ini_get('memory_limit');
        $memory_available = $this->parse_memory_limit($memory_limit);

        // Only read if file size is reasonable compared to available memory
        if ($file_size > ($memory_available / 10)) { // Use max 10% of available memory
            error_log('TWSS Security: File too large for safe reading: ' . $file_path);
            return false;
        }

        // Security: Read with error handling
        $content = @file_get_contents($file_path);
        if ($content === false) {
            return false;
        }

        // Security: Additional content validation
        if (strlen($content) > 1048576) { // 1MB hard limit
            error_log('TWSS Security: File content too large, truncating: ' . $file_path);
            $content = substr($content, 0, 1048576);
        }

        return $content;
    }

    /**
     * Parse memory limit string to bytes
     *
     * @since    1.0.32
     * @param    string    $limit    Memory limit string (e.g., "128M", "1G")
     * @return   int       Memory limit in bytes
     * @security Helper for memory management
     */
    private function parse_memory_limit($limit)
    {
        $limit = trim($limit);
        $last_char = strtolower($limit[strlen($limit) - 1]);
        $number = (int)$limit;

        switch ($last_char) {
            case 'g':
                $number *= 1024 * 1024 * 1024;
                break;
            case 'm':
                $number *= 1024 * 1024;
                break;
            case 'k':
                $number *= 1024;
                break;
        }

        return $number;
    }

    /**
     * Analyze file with OpenAI
     *
     * @since    1.0.0
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Analysis result
     */
    private function analyze_with_openai($file_path, $file_content, $file_extension)
    {
        try {
            $prompt = $this->build_analysis_prompt($file_path, $file_content, $file_extension);

            $result = $this->send_openai_request($prompt);

            return $this->parse_ai_response($result);
        } catch (Exception $e) {
            // In case of API failure, fall back to simple analysis
            return $this->analyze_with_fallback($file_path, $file_content, $file_extension);
        }
    }

    /**
     * Analyze file with Gemini
     *
     * @since    1.0.0
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Analysis result
     */
    private function analyze_with_gemini($file_path, $file_content, $file_extension)
    {
        try {
            $prompt = $this->build_analysis_prompt($file_path, $file_content, $file_extension);

            $result = $this->send_gemini_request($prompt);

            return $this->parse_ai_response($result);
        } catch (Exception $e) {
            // In case of API failure, fall back to simple analysis
            return $this->analyze_with_fallback($file_path, $file_content, $file_extension);
        }
    }

    /**
     * Analyze file with OpenRouter
     *
     * @since    1.0.27
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Analysis result
     */
    private function analyze_with_openrouter($file_path, $file_content, $file_extension)
    {
        try {
            $prompt = $this->build_analysis_prompt($file_path, $file_content, $file_extension);

            $result = $this->send_openrouter_request($prompt);

            return $this->parse_ai_response($result);
        } catch (Exception $e) {
            // In case of API failure, fall back to simple analysis
            return $this->analyze_with_fallback($file_path, $file_content, $file_extension);
        }
    }

    /**
     * Analyze file with Groq API
     *
     * @since    1.0.31
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Analysis result
     */
    private function analyze_with_groq($file_path, $file_content, $file_extension)
    {
        try {
            $prompt = $this->build_analysis_prompt($file_path, $file_content, $file_extension);

            $result = $this->send_groq_request($prompt);

            return $this->parse_ai_response($result);
        } catch (Exception $e) {
            // In case of API failure, fall back to simple analysis
            return $this->analyze_with_fallback($file_path, $file_content, $file_extension);
        }
    }

    /**
     * Analyze file with fallback method (no AI API)
     *
     * @since    1.0.0
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Analysis result
     */
    public function analyze_with_fallback($file_path, $file_content, $file_extension)
    {
        $analysis_result = $this->perform_comprehensive_malware_analysis($file_path, $file_content, $file_extension);

        return array(
            'is_malware' => $analysis_result['is_malicious'],
            'explanation' => $analysis_result['explanation'],
            'suggested_fix' => $analysis_result['suggested_action'],
            'confidence' => $analysis_result['confidence'],
            'indicators' => $analysis_result['indicators']
        );
    }

    /**
     * Perform comprehensive malware analysis using expert patterns
     *
     * @since    1.0.24
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Detailed analysis result
     */
    private function perform_comprehensive_malware_analysis($file_path, $file_content, $file_extension)
    {
        $indicators = array();
        $confidence = 0;
        $is_malicious = false;
        $explanation = '';
        $suggested_action = 'none';

        // 1. OBFUSCATION DETECTION (High Priority)
        $obfuscation_result = $this->detect_obfuscation_techniques($file_content);
        if ($obfuscation_result['detected']) {
            $indicators = array_merge($indicators, $obfuscation_result['indicators']);
            $confidence += $obfuscation_result['confidence'];
            $is_malicious = true;
            $explanation = 'Code obfuscation detected: ' . implode(', ', $obfuscation_result['indicators']);
            $suggested_action = 'quarantine';
        }

        // 2. BACKDOOR AND SHELL DETECTION
        $backdoor_result = $this->detect_backdoors_and_shells($file_content);
        if ($backdoor_result['detected']) {
            $indicators = array_merge($indicators, $backdoor_result['indicators']);
            $confidence += $backdoor_result['confidence'];
            $is_malicious = true;
            $explanation = 'Backdoor/Shell detected: ' . implode(', ', $backdoor_result['indicators']);
            $suggested_action = 'delete';
        }

        // 3. MALICIOUS FUNCTION USAGE
        $function_result = $this->detect_malicious_functions($file_content, $file_extension);
        if ($function_result['detected']) {
            $indicators = array_merge($indicators, $function_result['indicators']);
            $confidence += $function_result['confidence'];
            if ($function_result['high_risk']) {
                $is_malicious = true;
                $explanation = 'High-risk functions detected: ' . implode(', ', $function_result['indicators']);
                $suggested_action = 'quarantine';
            }
        }

        // 4. SUSPICIOUS FILE LOCATIONS
        $location_result = $this->analyze_file_location($file_path, $file_extension);
        if ($location_result['suspicious']) {
            $indicators = array_merge($indicators, $location_result['indicators']);
            $confidence += $location_result['confidence'];
            $is_malicious = true;
            $explanation = 'Suspicious file location: ' . $location_result['reason'];
            $suggested_action = 'quarantine';
        }

        // 5. ENCODING AND ENCRYPTION PATTERNS
        $encoding_result = $this->detect_malicious_encoding($file_content);
        if ($encoding_result['detected']) {
            $indicators = array_merge($indicators, $encoding_result['indicators']);
            $confidence += $encoding_result['confidence'];
            if ($confidence > 70) {
                $is_malicious = true;
                $explanation = 'Malicious encoding patterns: ' . implode(', ', $encoding_result['indicators']);
                $suggested_action = 'quarantine';
            }
        }

        // 6. NETWORK COMMUNICATION PATTERNS
        $network_result = $this->detect_network_communication($file_content);
        if ($network_result['detected']) {
            $indicators = array_merge($indicators, $network_result['indicators']);
            $confidence += $network_result['confidence'];
            if ($network_result['high_risk']) {
                $is_malicious = true;
                $explanation = 'Suspicious network communication: ' . implode(', ', $network_result['indicators']);
                $suggested_action = 'quarantine';
            }
        }

        // 7. WORDPRESS-SPECIFIC MALWARE PATTERNS
        $wp_result = $this->detect_wordpress_specific_malware($file_content, $file_path);
        if ($wp_result['detected']) {
            $indicators = array_merge($indicators, $wp_result['indicators']);
            $confidence += $wp_result['confidence'];
            $is_malicious = true;
            $explanation = 'WordPress-specific malware: ' . implode(', ', $wp_result['indicators']);
            $suggested_action = 'delete';
        }

        // Cap confidence at 100
        $confidence = min($confidence, 100);

        return array(
            'is_malicious' => $is_malicious,
            'confidence' => $confidence,
            'explanation' => $explanation ?: 'No malware indicators detected',
            'suggested_action' => $suggested_action,
            'indicators' => array_unique($indicators)
        );
    }

    /**
     * Detect various obfuscation techniques used by malware
     *
     * @since    1.0.24
     * @param    string    $content    File content
     * @return   array     Detection result
     */
    private function detect_obfuscation_techniques($content)
    {
        $indicators = array();
        $confidence = 0;

        // 1. Base64 encoding patterns
        if (preg_match_all('/["\']([A-Za-z0-9+\/]{50,}={0,2})["\']/', $content, $matches)) {
            foreach ($matches[1] as $encoded) {
                $decoded = base64_decode($encoded, true);
                if ($decoded !== false && $this->contains_php_code($decoded)) {
                    $indicators[] = 'Base64-encoded PHP code';
                    $confidence += 30;
                    break;
                }
            }
        }

        // 2. Hexadecimal encoding
        if (preg_match('/\\\\x[0-9a-fA-F]{2,}/', $content)) {
            $indicators[] = 'Hexadecimal encoding detected';
            $confidence += 20;
        }

        // 3. Character code obfuscation
        if (preg_match('/chr\s*\(\s*\d+\s*\)/', $content) && substr_count($content, 'chr(') > 5) {
            $indicators[] = 'Character code obfuscation';
            $confidence += 25;
        }

        // 4. String concatenation obfuscation
        if (preg_match_all('/["\'][^"\']{1,3}["\'](\s*\.\s*["\'][^"\']{1,3}["\']){10,}/', $content)) {
            $indicators[] = 'String concatenation obfuscation';
            $confidence += 20;
        }

        // 5. Excessive use of variables for simple strings
        if (preg_match_all('/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][^"\']{1,5}["\'];/', $content) > 20) {
            $indicators[] = 'Variable-based string obfuscation';
            $confidence += 15;
        }

        // 6. gzinflate/gzuncompress patterns
        if (preg_match('/gz(inflate|uncompress)\s*\(/', $content)) {
            $indicators[] = 'Compressed code obfuscation';
            $confidence += 35;
        }

        // 7. ROT13 or similar simple ciphers
        if (preg_match('/str_rot13\s*\(/', $content)) {
            $indicators[] = 'ROT13 obfuscation';
            $confidence += 25;
        }

        // 8. Excessive whitespace or formatting anomalies
        if ($this->has_suspicious_formatting($content)) {
            $indicators[] = 'Suspicious code formatting';
            $confidence += 10;
        }

        return array(
            'detected' => !empty($indicators),
            'indicators' => $indicators,
            'confidence' => $confidence
        );
    }

    /**
     * Detect backdoors and web shells
     *
     * @since    1.0.24
     * @param    string    $content    File content
     * @return   array     Detection result
     */
    private function detect_backdoors_and_shells($content)
    {
        $indicators = array();
        $confidence = 0;

        // Common backdoor patterns
        $backdoor_patterns = array(
            '/password.*=.*["\'][^"\']*["\']/' => 'Hardcoded password',
            '/if\s*\(\s*\$_POST\[.*\]\s*==.*\)/' => 'POST-based authentication',
            '/if\s*\(\s*md5\s*\(\s*\$_/' => 'MD5 hash authentication',
            '/passthru\s*\(\s*\$_/' => 'Command execution via passthru',
            '/system\s*\(\s*\$_/' => 'Command execution via system',
            '/exec\s*\(\s*\$_/' => 'Command execution via exec',
            '/shell_exec\s*\(\s*\$_/' => 'Command execution via shell_exec',
            '/\$_FILES.*move_uploaded_file/' => 'File upload functionality',
            '/file_get_contents\s*\(\s*["\']https?:\/\//' => 'Remote file inclusion',
            '/curl_exec\s*\(/' => 'CURL-based communication',
            '/fwrite\s*\(.*\$_/' => 'File writing from user input',
            '/eval\s*\(\s*\$_/' => 'Dynamic code execution'
        );

        foreach ($backdoor_patterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $indicators[] = $description;
                $confidence += 25;
            }
        }

        // Web shell signatures
        $shell_signatures = array(
            'c99shell',
            'r57shell',
            'wso shell',
            'b374k',
            'adminer',
            'shell_exec',
            'FilesMan',
            'Uname:',
            'Server IP:',
            'phpinfo()',
            'Safe Mode:',
            'eval($_POST',
            'assert($_POST',
            '$_POST[\'cmd\']'
        );

        foreach ($shell_signatures as $signature) {
            if (stripos($content, $signature) !== false) {
                $indicators[] = "Web shell signature: {$signature}";
                $confidence += 30;
            }
        }

        return array(
            'detected' => !empty($indicators),
            'indicators' => $indicators,
            'confidence' => $confidence
        );
    }

    /**
     * Detect malicious function usage
     *
     * @since    1.0.24
     * @param    string    $content    File content
     * @param    string    $extension  File extension
     * @return   array     Detection result
     */
    private function detect_malicious_functions($content, $extension)
    {
        $indicators = array();
        $confidence = 0;
        $high_risk = false;

        // High-risk PHP functions
        $high_risk_functions = array(
            'eval',
            'assert',
            'create_function',
            'preg_replace.*\/e',
            'system',
            'exec',
            'passthru',
            'shell_exec',
            'popen',
            'proc_open',
            'proc_close',
            'proc_get_status',
            'proc_nice',
            'proc_terminate',
            'escapeshellarg',
            'escapeshellcmd'
        );

        foreach ($high_risk_functions as $func) {
            if (preg_match("/{$func}\s*\(/", $content)) {
                $indicators[] = "High-risk function: {$func}()";
                $confidence += 20;
                $high_risk = true;
            }
        }

        // Moderate-risk functions (context-dependent)
        $moderate_risk_functions = array(
            'base64_decode',
            'base64_encode',
            'gzinflate',
            'gzdeflate',
            'str_rot13',
            'convert_uuencode',
            'convert_uudecode',
            'file_get_contents',
            'file_put_contents',
            'fopen',
            'fwrite',
            'fputs',
            'fgets',
            'fread',
            'include',
            'require',
            'include_once',
            'require_once'
        );

        $moderate_count = 0;
        foreach ($moderate_risk_functions as $func) {
            if (preg_match("/{$func}\s*\(/", $content)) {
                $moderate_count++;
                if ($moderate_count > 3) { // Multiple moderate functions = suspicious
                    $indicators[] = "Multiple encoding/file functions detected";
                    $confidence += 15;
                    break;
                }
            }
        }

        // JavaScript suspicious functions
        if ($extension === 'js') {
            $js_suspicious = array('eval', 'Function', 'setTimeout', 'setInterval');
            foreach ($js_suspicious as $func) {
                if (preg_match("/{$func}\s*\(/", $content)) {
                    $indicators[] = "Suspicious JavaScript function: {$func}()";
                    $confidence += 15;
                }
            }
        }

        return array(
            'detected' => !empty($indicators),
            'indicators' => $indicators,
            'confidence' => $confidence,
            'high_risk' => $high_risk
        );
    }

    /**
     * Analyze file location for suspicious placement
     *
     * @since    1.0.24
     * @param    string    $file_path   File path
     * @param    string    $extension   File extension
     * @return   array     Analysis result
     */
    private function analyze_file_location($file_path, $extension)
    {
        $indicators = array();
        $confidence = 0;
        $suspicious = false;
        $reason = '';

        // PHP files in uploads directory (almost always malicious)
        if ($extension === 'php' && strpos($file_path, 'wp-content/uploads') !== false) {
            $indicators[] = 'PHP file in uploads directory';
            $confidence = 90;
            $suspicious = true;
            $reason = 'PHP files should not exist in wp-content/uploads directory';
        }

        // Hidden files (starting with .)
        $filename = basename($file_path);
        if ($filename[0] === '.' && strlen($filename) > 1) {
            $indicators[] = 'Hidden file';
            $confidence += 20;
            $suspicious = true;
            $reason = 'Hidden files are often used to conceal malicious code';
        }

        // Suspicious file names
        $suspicious_names = array(
            'index.php',
            'wp-config.php',
            '.htaccess',
            'shell.php',
            'cmd.php',
            'admin.php',
            'login.php',
            'wp-blog-header.php'
        );

        foreach ($suspicious_names as $sus_name) {
            if ($filename === $sus_name && !$this->is_legitimate_location($file_path, $sus_name)) {
                $indicators[] = "Suspicious filename: {$sus_name}";
                $confidence += 25;
                $suspicious = true;
                $reason = "File {$sus_name} found in unexpected location";
            }
        }

        // Temp or cache directories with executable files
        if (preg_match('#\/(tmp|temp|cache|log)\/.*\.(php|js|html)$#i', $file_path)) {
            $indicators[] = 'Executable file in temp directory';
            $confidence += 30;
            $suspicious = true;
            $reason = 'Executable files in temporary directories are suspicious';
        }

        return array(
            'suspicious' => $suspicious,
            'indicators' => $indicators,
            'confidence' => $confidence,
            'reason' => $reason
        );
    }

    /**
     * Detect malicious encoding patterns
     *
     * @since    1.0.24
     * @param    string    $content    File content
     * @return   array     Detection result
     */
    private function detect_malicious_encoding($content)
    {
        $indicators = array();
        $confidence = 0;

        // Multiple base64 strings (potential obfuscation)
        $base64_matches = preg_match_all('/[A-Za-z0-9+\/]{30,}={0,2}/', $content);
        if ($base64_matches > 5) {
            $indicators[] = 'Multiple base64 encoded strings';
            $confidence += 20;
        }

        // URL encoding patterns
        if (preg_match_all('/%[0-9a-fA-F]{2}/', $content) > 10) {
            $indicators[] = 'Extensive URL encoding';
            $confidence += 15;
        }

        // Unicode escape sequences
        if (preg_match('/\\\\u[0-9a-fA-F]{4}/', $content)) {
            $indicators[] = 'Unicode escape sequences';
            $confidence += 10;
        }

        return array(
            'detected' => !empty($indicators),
            'indicators' => $indicators,
            'confidence' => $confidence
        );
    }

    /**
     * Detect suspicious network communication
     *
     * @since    1.0.24
     * @param    string    $content    File content
     * @return   array     Detection result
     */
    private function detect_network_communication($content)
    {
        $indicators = array();
        $confidence = 0;
        $high_risk = false;

        // Remote file inclusion
        if (preg_match('#file_get_contents\s*\(\s*["\']https?:\/\/#', $content)) {
            $indicators[] = 'Remote file inclusion detected';
            $confidence += 25;
            $high_risk = true;
        }

        // CURL usage (context-dependent)
        if (preg_match('/curl_init|curl_exec/', $content)) {
            $indicators[] = 'CURL network communication';
            $confidence += 15;
        }

        // Suspicious domains or IPs
        $suspicious_patterns = array(
            '/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/' => 'Hardcoded IP with port',
            '/\.tk\/|\.ml\/|\.ga\/|\.cf\//' => 'Suspicious TLD domain',
            '/pastebin\.com|bit\.ly|tinyurl\.com/' => 'URL shortening service'
        );

        foreach ($suspicious_patterns as $pattern => $desc) {
            if (preg_match($pattern, $content)) {
                $indicators[] = $desc;
                $confidence += 20;
                $high_risk = true;
            }
        }

        return array(
            'detected' => !empty($indicators),
            'indicators' => $indicators,
            'confidence' => $confidence,
            'high_risk' => $high_risk
        );
    }

    /**
     * Detect WordPress-specific malware patterns
     *
     * @since    1.0.24
     * @param    string    $content    File content
     * @param    string    $file_path  File path
     * @return   array     Detection result
     */
    private function detect_wordpress_specific_malware($content, $file_path)
    {
        $indicators = array();
        $confidence = 0;

        // Admin user creation
        if (preg_match('/wp_create_user|wp_insert_user.*administrator/', $content)) {
            $indicators[] = 'Automatic admin user creation';
            $confidence += 40;
        }

        // Database manipulation
        if (preg_match('/\$wpdb.*INSERT.*wp_users/', $content)) {
            $indicators[] = 'Direct user database manipulation';
            $confidence += 35;
        }

        // Hooks for malicious purposes
        $malicious_hooks = array(
            'wp_head',
            'wp_footer',
            'init',
            'wp_loaded'
        );

        foreach ($malicious_hooks as $hook) {
            if (preg_match("/add_action\s*\(\s*['\"]" . $hook . "['\"].*(\\\$_POST|\\\$_GET|eval)/", $content)) {
                $indicators[] = "Malicious WordPress hook: {$hook}";
                $confidence += 30;
            }
        }

        // Fake WordPress files
        if (basename($file_path) === 'wp-config.php' && !preg_match('/DB_NAME|DB_USER|DB_PASSWORD/', $content)) {
            $indicators[] = 'Fake wp-config.php file';
            $confidence += 50;
        }

        return array(
            'detected' => !empty($indicators),
            'indicators' => $indicators,
            'confidence' => $confidence
        );
    }

    /**
     * Check if content contains PHP code
     *
     * @since    1.0.24
     * @param    string    $content    Content to check
     * @return   boolean   True if contains PHP code
     */
    private function contains_php_code($content)
    {
        return strpos($content, '<?php') !== false || strpos($content, '<?=') !== false ||
            preg_match('/\$[a-zA-Z_]/', $content);
    }

    /**
     * Check for suspicious formatting patterns
     *
     * @since    1.0.24
     * @param    string    $content    Content to check
     * @return   boolean   True if formatting is suspicious
     */
    private function has_suspicious_formatting($content)
    {
        // Very long lines (potential obfuscation)
        if (preg_match('/^.{500,}$/m', $content)) {
            return true;
        }

        // Excessive semicolons on one line
        if (preg_match('/.*;.*;.*;.*/', $content)) {
            return true;
        }

        // No whitespace around operators (packed code)
        $operators = preg_match_all('/[a-zA-Z0-9]\+[a-zA-Z0-9]|[a-zA-Z0-9]\-[a-zA-Z0-9]/', $content);
        if ($operators > 20) {
            return true;
        }

        return false;
    }

    /**
     * Check if file is in legitimate location
     *
     * @since    1.0.24
     * @param    string    $file_path  File path
     * @param    string    $filename   Filename
     * @return   boolean   True if location is legitimate
     */
    private function is_legitimate_location($file_path, $filename)
    {
        $legitimate_locations = array(
            'wp-config.php' => array('/wp-config.php'),
            'index.php' => array('/index.php', '/wp-admin/index.php'),
            '.htaccess' => array('/.htaccess', '/wp-admin/.htaccess'),
        );

        if (!isset($legitimate_locations[$filename])) {
            return true; // Unknown file, assume legitimate
        }

        foreach ($legitimate_locations[$filename] as $legit_path) {
            if (strpos($file_path, $legit_path) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Send request to OpenAI API
     *
     * @since    1.0.0
     * @param    string    $prompt    The prompt for the AI
     * @return   string    The AI response
     */
    private function send_openai_request($prompt)
    {
        $api_key = $this->openai_client->api_key;
        $url = 'https://api.openai.com/v1/chat/completions';

        $headers = array(
            'Content-Type: application/json',
            'Authorization: Bearer ' . $api_key
        );

        $data = array(
            'model' => 'gpt-4-turbo',
            'messages' => array(
                array(
                    'role' => 'system',
                    'content' => 'You are a cybersecurity expert specialized in WordPress security and malware analysis.'
                ),
                array(
                    'role' => 'user',
                    'content' => $prompt
                )
            ),
            'temperature' => 0.2,
            'max_tokens' => 500
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            $this->rate_limited_error_log("OpenAI API cURL Error: {$err}");
            throw new Exception('API request error: ' . $err);
        }

        $response_data = json_decode($response, true);

        if (isset($response_data['choices'][0]['message']['content'])) {
            return $response_data['choices'][0]['message']['content'];
        } else {
            // Handle specific API errors
            if (isset($response_data['error'])) {
                $error = $response_data['error'];
                $error_code = isset($error['code']) ? $error['code'] : 0;
                $error_message = isset($error['message']) ? $error['message'] : 'Unknown API error';

                // Handle quota/credit exhausted errors with aggressive rate limiting
                if ($error_code === 429 || strpos($error_message, 'quota') !== false || strpos($error_message, 'credit') !== false) {
                    // Only log this error once every 30 minutes (1800 seconds) to prevent spam
                    $this->rate_limited_error_log('OpenAI API Quota/Credits Exhausted - Falling back to pattern-based analysis', 1800);
                    throw new Exception('AI analysis temporarily unavailable due to quota limits. Using pattern-based analysis instead.');
                }

                // Handle rate limiting with reduced logging
                if ($error_code === 429) {
                    $this->rate_limited_error_log('OpenAI API Rate Limited - Using pattern analysis', 900);
                    throw new Exception('AI service rate limited. Falling back to pattern analysis.');
                }

                // Handle other API errors with rate limiting
                $this->rate_limited_error_log("OpenAI API Error [{$error_code}]: {$error_message}");
                throw new Exception("AI analysis service error. Using pattern-based detection instead.");
            }

            $this->rate_limited_error_log('OpenAI API: Invalid response structure received');
            throw new Exception('Invalid API response');
        }
    }

    /**
     * Send request to Gemini API
     *
     * @since    1.0.0
     * @param    string    $prompt    The prompt for the AI
     * @return   string    The AI response
     */
    private function send_gemini_request($prompt)
    {
        $api_key = $this->gemini_client->api_key;
        // Updated to use the correct model name
        $url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . $api_key;

        $headers = array(
            'Content-Type: application/json'
        );

        $data = array(
            'contents' => array(
                array(
                    'parts' => array(
                        array(
                            'text' => $prompt
                        )
                    )
                )
            ),
            'generationConfig' => array(
                'temperature' => 0.2,
                'maxOutputTokens' => 500
            )
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            $this->rate_limited_error_log("Gemini API cURL Error: {$err}");
            throw new Exception('API request error: ' . $err);
        }

        $response_data = json_decode($response, true);

        if (isset($response_data['candidates'][0]['content']['parts'][0]['text'])) {
            return $response_data['candidates'][0]['content']['parts'][0]['text'];
        } else {
            // Handle specific API errors
            if (isset($response_data['error'])) {
                $error = $response_data['error'];
                $error_code = isset($error['code']) ? $error['code'] : 0;
                $error_message = isset($error['message']) ? $error['message'] : 'Unknown API error';
                $error_status = isset($error['status']) ? $error['status'] : 'UNKNOWN';

                // Handle quota exhausted error (429) with aggressive rate limiting
                if ($error_code === 429 || $error_status === 'RESOURCE_EXHAUSTED') {
                    // Only log this error once every 30 minutes (1800 seconds) to prevent spam
                    $this->rate_limited_error_log('Gemini API Quota Exhausted - Falling back to pattern-based analysis', 1800);
                    throw new Exception('AI analysis temporarily unavailable due to quota limits. Using pattern-based analysis instead.');
                }

                // Handle rate limiting
                if ($error_code === 429) {
                    $this->rate_limited_error_log('Gemini API Rate Limited - Using pattern analysis', 900);
                    throw new Exception('AI service rate limited. Falling back to pattern analysis.');
                }

                // Handle other API errors with sanitized messages and rate limiting
                $this->rate_limited_error_log("Gemini API Error [{$error_code}]: {$error_message}");
                throw new Exception("AI analysis service error. Using pattern-based detection instead.");
            }

            // Log raw response for debugging (but sanitize in production) with rate limiting
            $this->rate_limited_error_log('Gemini API: Invalid response structure received');
            throw new Exception('AI service returned invalid response. Using fallback analysis.');
        }
    }

    /**
     * Rate limiting for error logging
     *
     * @since    1.0.28
     * @access   private
     * @var      array    $error_log_cache
     */
    private static $error_log_cache = array();

    /**
     * Rate limited error logging
     *
     * @since    1.0.28
     * @param    string    $message    Error message
     * @param    int       $timeout    Rate limit timeout in seconds (default: 300 = 5 minutes)
     * @return   boolean   True if message was logged, false if rate limited
     */
    private function rate_limited_error_log($message, $timeout = 300)
    {
        $hash = md5($message);
        $now = time();

        // Check if we've logged this error recently
        if (
            isset(self::$error_log_cache[$hash]) &&
            (self::$error_log_cache[$hash] + $timeout) > $now
        ) {
            return false; // Rate limited
        }

        // Log the error and update cache
        error_log($message);
        self::$error_log_cache[$hash] = $now;

        // Clean up old cache entries periodically
        if (count(self::$error_log_cache) > 50) {
            $this->cleanup_error_log_cache($timeout);
        }

        return true;
    }

    /**
     * Clean up old error log cache entries
     *
     * @since    1.0.28
     * @param    int    $timeout    Timeout to use for cleanup
     */
    private function cleanup_error_log_cache($timeout = 300)
    {
        $now = time();
        foreach (self::$error_log_cache as $key => $time) {
            if (($time + $timeout) <= $now) {
                unset(self::$error_log_cache[$key]);
            }
        }
    }

    /**
     * Clear all error log cache (useful for cleanup)
     *
     * @since    1.0.28
     */
    public static function clear_error_log_cache()
    {
        self::$error_log_cache = array();
    }

    /**
     * Send request to OpenRouter API
     *
     * @since    1.0.27
     * @param    string    $prompt    The prompt for the AI
     * @return   string    The AI response
     */
    private function send_openrouter_request($prompt)
    {
        $api_key = $this->openrouter_client->api_key;
        $url = 'https://openrouter.ai/api/v1/chat/completions';

        // Get the actual website URL for tracking with fallback
        $site_url = function_exists('get_site_url') ? get_site_url() : 'http://localhost';
        $site_name = function_exists('get_bloginfo') ? get_bloginfo('name') : 'WordPress Site';

        $headers = array(
            'Content-Type: application/json',
            'Authorization: Bearer ' . $api_key,
            'HTTP-Referer: ' . $site_url,
            'X-Title: WordPress Security Scanner - ' . $site_name
        );

        $data = array(
            'model' => function_exists('get_option') ? get_option('twss_openrouter_model', 'openai/gpt-3.5-turbo') : 'openai/gpt-3.5-turbo',
            'messages' => array(
                array(
                    'role' => 'system',
                    'content' => 'You are a cybersecurity expert specialized in WordPress security and malware analysis.'
                ),
                array(
                    'role' => 'user',
                    'content' => $prompt
                )
            ),
            'temperature' => 0.2,
            'max_tokens' => 500
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            $this->rate_limited_error_log("OpenRouter API cURL Error: {$err}");
            throw new Exception('API request error: ' . $err);
        }

        $response_data = json_decode($response, true);

        if (isset($response_data['choices'][0]['message']['content'])) {
            return $response_data['choices'][0]['message']['content'];
        } else {
            // Handle specific API errors
            if (isset($response_data['error'])) {
                $error = $response_data['error'];
                $error_code = isset($error['code']) ? $error['code'] : 0;
                $error_message = isset($error['message']) ? $error['message'] : 'Unknown API error';
                $error_type = isset($error['type']) ? $error['type'] : 'UNKNOWN';

                // Handle model not found errors (404)
                if ($error_code === 404 && strpos($error_message, 'endpoints') !== false) {
                    $this->rate_limited_error_log("OpenRouter Model Not Available: {$error_message} - Trying fallback model");

                    // Try with a reliable fallback model
                    $fallback_models = ['openai/gpt-3.5-turbo', 'anthropic/claude-3-haiku', 'google/gemma-2-9b-it:free', 'meta-llama/llama-3-8b-instruct:free'];
                    $current_model = function_exists('get_option') ? get_option('twss_openrouter_model', 'openai/gpt-3.5-turbo') : 'openai/gpt-3.5-turbo';

                    foreach ($fallback_models as $fallback_model) {
                        if ($fallback_model !== $current_model) {
                            // Update model setting and retry
                            if (function_exists('update_option')) {
                                update_option('twss_openrouter_model', $fallback_model);
                            }
                            $this->rate_limited_error_log("Switching to fallback model: {$fallback_model}");
                            throw new Exception("Model not available. Switched to {$fallback_model}. Please retry your request.");
                        }
                    }

                    throw new Exception('Current model unavailable and fallback models failed. Please check OpenRouter model availability.');
                }

                // Handle quota/credit exhausted errors with aggressive rate limiting
                if ($error_code === 429 || strpos($error_message, 'quota') !== false || strpos($error_message, 'credit') !== false) {
                    // Only log this error once every 30 minutes (1800 seconds) to prevent spam
                    $this->rate_limited_error_log('OpenRouter API Quota/Credits Exhausted - Falling back to pattern-based analysis', 1800);
                    throw new Exception('AI analysis temporarily unavailable due to quota limits. Using pattern-based analysis instead.');
                }

                // Handle rate limiting with reduced logging
                if ($error_code === 429) {
                    $this->rate_limited_error_log('OpenRouter API Rate Limited - Using pattern analysis', 900);
                    throw new Exception('AI service rate limited. Falling back to pattern analysis.');
                }

                // Handle Invalid JSON errors (often temporary)
                if ($error_code === 400 && strpos($error_message, 'Invalid JSON') !== false) {
                    $this->rate_limited_error_log("OpenRouter API Error [{$error_code}]: {$error_message}", 600);
                    throw new Exception("AI analysis service error. Using pattern-based detection instead.");
                }

                // Handle other API errors with sanitized messages
                $this->rate_limited_error_log("OpenRouter API Error [{$error_code}]: {$error_message}");
                throw new Exception("AI analysis service error. Using pattern-based detection instead.");
            }

            // Log for debugging with rate limiting
            $this->rate_limited_error_log('OpenRouter API: Invalid response structure received');
            throw new Exception('AI service returned invalid response. Using fallback analysis.');
        }
    }

    /**
     * Send request to Groq API
     *
     * @since    1.0.31
     * @param    string    $prompt    The prompt to send to the API
     * @return   string              The API response
     * @throws   Exception           On API error
     */
    private function send_groq_request($prompt)
    {
        $api_key = $this->groq_client->api_key;
        $url = 'https://api.groq.com/openai/v1/chat/completions';

        $headers = array(
            'Content-Type: application/json',
            'Authorization: Bearer ' . $api_key
        );

        $data = array(
            'model' => function_exists('get_option') ? get_option('twss_groq_model', 'llama-3.3-70b-versatile') : 'llama-3.3-70b-versatile',
            'messages' => array(
                array(
                    'role' => 'system',
                    'content' => 'You are a cybersecurity expert specialized in WordPress security and malware analysis.'
                ),
                array(
                    'role' => 'user',
                    'content' => $prompt
                )
            ),
            'temperature' => 0.2,
            'max_tokens' => 500
        );

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            $this->rate_limited_error_log("Groq API cURL Error: {$err}");
            throw new Exception('API request error: ' . $err);
        }

        $response_data = json_decode($response, true);

        if (isset($response_data['choices'][0]['message']['content'])) {
            return $response_data['choices'][0]['message']['content'];
        } else {
            // Handle specific API errors
            if (isset($response_data['error'])) {
                $error = $response_data['error'];
                $error_code = isset($error['code']) ? $error['code'] : 0;
                $error_message = isset($error['message']) ? $error['message'] : 'Unknown API error';

                // Handle quota/credit exhausted errors
                if ($error_code === 429 || strpos($error_message, 'quota') !== false || strpos($error_message, 'rate') !== false) {
                    $this->rate_limited_error_log('Groq API Rate Limited - Falling back to pattern-based analysis', 900);
                    throw new Exception('AI analysis temporarily unavailable due to rate limits. Using pattern-based analysis instead.');
                }

                // Handle other API errors
                $this->rate_limited_error_log("Groq API Error [{$error_code}]: {$error_message}");
                throw new Exception("AI analysis service error. Using pattern-based detection instead.");
            }

            // Log for debugging with rate limiting
            $this->rate_limited_error_log('Groq API: Invalid response structure received');
            throw new Exception('AI service returned invalid response. Using fallback analysis.');
        }
    }

    /**
     * Build prompt for AI analysis
     *
     * @since    1.0.0
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   string    The prompt
     */
    private function build_analysis_prompt($file_path, $file_content, $file_extension)
    {
        $prompt = "You are an expert malware analyst specializing in WordPress security.\n\n";

        $prompt .= "ANALYSIS TARGET:\n";
        $prompt .= "File: " . basename($file_path) . "\n";
        $prompt .= "Path: " . $file_path . "\n";
        $prompt .= "Type: " . strtoupper($file_extension) . " file\n\n";

        $prompt .= "FILE CONTENT:\n```" . $file_extension . "\n" . $file_content . "\n```\n\n";

        $prompt .= "CRITICAL ANALYSIS INSTRUCTIONS:\n";
        $prompt .= "Analyze this file for malware with expert-level scrutiny. Look for:\n\n";

        $prompt .= "🔍 OBFUSCATION TECHNIQUES:\n";
        $prompt .= "- Base64/hex encoding of PHP code\n";
        $prompt .= "- Character code concatenation (chr() functions)\n";
        $prompt .= "- String concatenation to hide function names\n";
        $prompt .= "- gzinflate/gzuncompress compression\n";
        $prompt .= "- Variable-based string construction\n";
        $prompt .= "- ROT13 or other cipher obfuscation\n\n";

        $prompt .= "🚪 BACKDOORS & SHELLS:\n";
        $prompt .= "- Password-protected command execution\n";
        $prompt .= "- File upload/download functionality\n";
        $prompt .= "- Remote command execution (system, exec, shell_exec)\n";
        $prompt .= "- eval() or assert() with user input\n";
        $prompt .= "- Web shell signatures (c99, r57, wso, etc.)\n\n";

        $prompt .= "🌐 NETWORK COMMUNICATION:\n";
        $prompt .= "- Remote file inclusion patterns\n";
        $prompt .= "- Suspicious CURL usage\n";
        $prompt .= "- Hardcoded IPs or suspicious domains\n";
        $prompt .= "- Data exfiltration attempts\n\n";

        $prompt .= "📍 LOCATION-BASED RISKS:\n";
        $prompt .= "- PHP files in wp-content/uploads (HIGH RISK)\n";
        $prompt .= "- Hidden files (starting with .)\n";
        $prompt .= "- Fake core WordPress files\n";
        $prompt .= "- Files in temp/cache directories\n\n";

        $prompt .= "🎯 WORDPRESS-SPECIFIC THREATS:\n";
        $prompt .= "- Unauthorized admin user creation\n";
        $prompt .= "- Direct database manipulation\n";
        $prompt .= "- Malicious hook implementations\n";
        $prompt .= "- Plugin/theme injection\n\n";

        $prompt .= "⚠️ DO NOT FLAG IF:\n";
        $prompt .= "- File is just minified JavaScript/CSS (legitimate optimization)\n";
        $prompt .= "- Base64 is used for legitimate data (images, fonts, etc.)\n";
        $prompt .= "- Functions are used in legitimate, well-structured code\n";
        $prompt .= "- File is a known legitimate WordPress core/plugin file\n\n";

        $prompt .= "✅ RESPONSE FORMAT (MANDATORY):\n";
        $prompt .= "MALICIOUS: [Yes/No]\n";
        $prompt .= "CONFIDENCE: [0-100]%\n";
        $prompt .= "EXPLANATION: [Detailed technical explanation of findings]\n";
        $prompt .= "INDICATORS: [Comma-separated list of specific indicators found]\n";
        $prompt .= "SUGGESTED_ACTION: [quarantine/delete/fix/monitor/none]\n";
        $prompt .= "FIX_PATCH: [If SUGGESTED_ACTION is 'fix', provide the exact corrected code snippet or specific removal instructions]\n\n";

        $prompt .= "IMPORTANT: Base your analysis on concrete evidence. If the file appears to be minified but legitimate, or if obfuscation serves a legitimate purpose (like code protection), do not flag it as malicious.\n\n";

        $prompt .= "FOR FIX_PATCH:\n";
        $prompt .= "- If malicious code can be safely removed, provide the cleaned code\n";
        $prompt .= "- If entire lines should be deleted, specify 'DELETE_LINES: [line_numbers]'\n";
        $prompt .= "- If code needs to be replaced, provide the exact replacement\n";
        $prompt .= "- Only provide patches for obvious malware, not for suspicious-but-uncertain code\n";

        return $prompt;
    }

    /**
     * Parse AI response into structured data
     *
     * @since    1.0.0
     * @param    string    $response    The AI response text
     * @return   array     Structured analysis result
     */
    private function parse_ai_response($response)
    {
        // Sanitize raw JSON response if it contains JSON
        $response = $this->sanitize_ai_response($response);

        // Default values
        $result = array(
            'is_malware' => false,
            'confidence' => 0,
            'explanation' => '',
            'suggested_fix' => 'none',
            'indicators' => array()
        );

        // Parse MALICIOUS field
        if (preg_match('/MALICIOUS:\s*(Yes|No)/i', $response, $matches)) {
            $result['is_malware'] = (strtolower($matches[1]) === 'yes');
        } else if (preg_match('/malware|malicious|suspicious|vulnerability|exploit|backdoor|security risk/i', $response)) {
            $result['is_malware'] = true;
        }

        // Parse CONFIDENCE field
        if (preg_match('/CONFIDENCE:\s*(\d+)%?/i', $response, $matches)) {
            $result['confidence'] = (int)$matches[1];
        } else {
            // Estimate confidence based on language used
            if ($result['is_malware']) {
                if (preg_match('/definitely|clearly|obviously|certain/i', $response)) {
                    $result['confidence'] = 90;
                } else if (preg_match('/likely|probably|appears to be/i', $response)) {
                    $result['confidence'] = 70;
                } else if (preg_match('/possibly|might be|could be/i', $response)) {
                    $result['confidence'] = 50;
                } else {
                    $result['confidence'] = 60; // Default for detected malware
                }
            } else {
                $result['confidence'] = 20; // Low confidence for clean files
            }
        }

        // Parse EXPLANATION field
        if (preg_match('/EXPLANATION:\s*(.+?)(?=INDICATORS:|SUGGESTED_ACTION:|$)/is', $response, $matches)) {
            $result['explanation'] = trim($matches[1]);
        } else {
            $result['explanation'] = $response;
        }

        // Parse INDICATORS field
        if (preg_match('/INDICATORS:\s*(.+?)(?=SUGGESTED_ACTION:|$)/is', $response, $matches)) {
            $indicators_string = trim($matches[1]);
            $result['indicators'] = array_map('trim', explode(',', $indicators_string));
        }

        // Parse SUGGESTED_ACTION field
        if (preg_match('/SUGGESTED_ACTION:\s*(quarantine|delete|fix|monitor|none)/i', $response, $matches)) {
            $result['suggested_fix'] = strtolower($matches[1]);
        } else {
            // Fallback logic based on content
            if ($result['is_malware']) {
                if (preg_match('/backdoor|shell|malicious/i', $response)) {
                    $result['suggested_fix'] = 'quarantine';
                } else if (preg_match('/delete|remove/i', $response)) {
                    $result['suggested_fix'] = 'delete';
                } else {
                    $result['suggested_fix'] = 'quarantine';
                }
            }
        }

        // Parse FIX_PATCH field
        if (preg_match('/FIX_PATCH:\s*(.+?)(?=\n\n|\n[A-Z]+:|\nIMPORTANT:|$)/is', $response, $matches)) {
            $result['fix_patch'] = trim($matches[1]);
        } else {
            $result['fix_patch'] = '';
        }

        return $result;
    }

    /**
     * Sanitize AI response to handle raw JSON or malformed responses
     *
     * @since    1.0.28
     * @param    string    $response    Raw AI response
     * @return   string    Sanitized response
     */
    private function sanitize_ai_response($response)
    {
        // Check if response is JSON
        if ($this->is_json($response)) {
            $json_data = json_decode($response, true);

            // If JSON decoding successful, extract the actual text response
            if (is_array($json_data)) {
                // Handle different AI response formats
                if (isset($json_data['choices'][0]['message']['content'])) {
                    // OpenAI format
                    return $json_data['choices'][0]['message']['content'];
                } elseif (isset($json_data['candidates'][0]['content']['parts'][0]['text'])) {
                    // Gemini format
                    return $json_data['candidates'][0]['content']['parts'][0]['text'];
                } elseif (isset($json_data['content'])) {
                    // Generic content field
                    return $json_data['content'];
                } elseif (isset($json_data['text'])) {
                    // Generic text field
                    return $json_data['text'];
                } elseif (isset($json_data['response'])) {
                    // Generic response field
                    return $json_data['response'];
                }
            }
        }

        // Clean up any JSON artifacts or escape sequences
        $cleaned = preg_replace('/\\\\["\\/bfnrt]/', ' ', $response);
        $cleaned = preg_replace('/[{}"\[\]]/', '', $cleaned);
        $cleaned = preg_replace('/\s+/', ' ', $cleaned);
        $cleaned = trim($cleaned);

        return $cleaned;
    }

    /**
     * Check if string is valid JSON
     *
     * @since    1.0.28
     * @param    string    $string    String to check
     * @return   boolean   True if valid JSON
     */
    private function is_json($string)
    {
        if (!is_string($string)) {
            return false;
        }

        json_decode($string);
        return (json_last_error() === JSON_ERROR_NONE);
    }

    /**
     * Truncate file content to safe size for API
     *
     * @since    1.0.0
     * @param    string    $content    File content
     * @param    int       $length     Maximum length
     * @return   string    Truncated content
     */
    private function truncate_file_content($content, $length = 10000)
    {
        if (strlen($content) <= $length) {
            return $content;
        }

        return substr($content, 0, $length) . "\n\n[Content truncated due to size limitation]";
    }

    /**
     * Check if content seems obfuscated
     *
     * @since    1.0.0
     * @param    string    $content    The content to check
     * @return   boolean   True if content seems obfuscated
     */
    private function seems_obfuscated($content)
    {
        // Check for very long lines
        if (preg_match('/^.{300,}$/m', $content)) {
            return true;
        }

        // Check for high ratio of special characters
        $special_chars = preg_match_all('/[\^\$\*\(\)\[\]\{\}\?\+\.\\\\]/', $content, $matches);
        $total_length = strlen($content);

        if ($total_length > 0 && ($special_chars / $total_length) > 0.1) {
            return true;
        }

        // Check for long encoded strings
        if (preg_match('/(\'|")([\w+\/=]{100,})(\'|")/', $content)) {
            return true;
        }

        return false;
    }

    /**
     * Test OpenAI API key
     *
     * @since    1.0.1
     * @param    string    $api_key    OpenAI API key to test
     * @return   array     Test result with success flag and message
     */
    public function test_openai_api_key($api_key)
    {
        try {
            $url = 'https://api.openai.com/v1/chat/completions';

            $headers = array(
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key
            );

            $data = array(
                'model' => 'gpt-3.5-turbo',
                'messages' => array(
                    array(
                        'role' => 'system',
                        'content' => 'You are a WordPress security expert.'
                    ),
                    array(
                        'role' => 'user',
                        'content' => 'Say "API connection successful" if you can read this message.'
                    )
                ),
                'temperature' => 0.2,
                'max_tokens' => 10
            );

            $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_TIMEOUT, 10);

            $response = curl_exec($curl);
            $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $err = curl_error($curl);

            curl_close($curl);

            if ($err) {
                return array(
                    'success' => false,
                    'message' => 'cURL Error: ' . $err
                );
            }

            if ($status !== 200) {
                $error_data = json_decode($response, true);
                $error_msg = isset($error_data['error']['message']) ? $error_data['error']['message'] : 'API returned status code ' . $status;
                return array(
                    'success' => false,
                    'message' => $error_msg
                );
            }

            return array(
                'success' => true,
                'message' => 'OpenAI API key is valid and working!'
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Test Gemini API key
     *
     * @since    1.0.1
     * @param    string    $api_key    Gemini API key to test
     * @return   array     Test result with success flag and message
     */
    public function test_gemini_api_key($api_key)
    {
        try {
            // Updated to use the correct model name
            $url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . $api_key;

            $headers = array(
                'Content-Type: application/json'
            );

            $data = array(
                'contents' => array(
                    array(
                        'parts' => array(
                            array(
                                'text' => 'Say "API connection successful" if you can read this message.'
                            )
                        )
                    )
                ),
                'generationConfig' => array(
                    'temperature' => 0.2,
                    'maxOutputTokens' => 10
                )
            );

            $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_TIMEOUT, 10);

            $response = curl_exec($curl);
            $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $err = curl_error($curl);

            curl_close($curl);

            if ($err) {
                return array(
                    'success' => false,
                    'message' => 'cURL Error: ' . $err
                );
            }

            if ($status !== 200) {
                $error_data = json_decode($response, true);
                $error_msg = isset($error_data['error']['message']) ? $error_data['error']['message'] : 'API returned status code ' . $status;
                return array(
                    'success' => false,
                    'message' => $error_msg
                );
            }

            return array(
                'success' => true,
                'message' => 'Google Gemini API key is valid and working!'
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Test OpenRouter API key and find available models
     *
     * @since    1.0.1
     * @param    string    $api_key    The OpenRouter API key to test
     * @return   array                 Success status, message, and available models
     */
    public function test_openrouter_api_key($api_key)
    {
        try {
            // First check if the API key is valid
            $headers = array(
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key
            );

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'https://openrouter.ai/api/v1/auth/key');
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_TIMEOUT, 10);

            $auth_response = curl_exec($curl);
            $auth_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $auth_err = curl_error($curl);
            curl_close($curl);

            if ($auth_err) {
                return array(
                    'success' => false,
                    'message' => 'Connection error: ' . $auth_err
                );
            }

            if ($auth_status !== 200) {
                return array(
                    'success' => false,
                    'message' => 'Invalid API key or connection failed'
                );
            }

            $auth_data = json_decode($auth_response, true);

            if (!isset($auth_data['data'])) {
                return array(
                    'success' => false,
                    'message' => 'Invalid API key format'
                );
            }

            $account_info = $auth_data['data'];
            $is_free_tier = isset($account_info['is_free_tier']) ? $account_info['is_free_tier'] : false;
            $usage = isset($account_info['usage']) ? $account_info['usage'] : 0;
            $limit_remaining = isset($account_info['limit_remaining']) ? $account_info['limit_remaining'] : null;

            // Test models in order of preference
            $test_models = array(
                'openai/gpt-3.5-turbo' => 'GPT-3.5 Turbo (Most reliable)',
                'anthropic/claude-3-haiku' => 'Claude 3 Haiku (Fast and accurate)',
                'google/gemma-2-9b-it:free' => 'Gemma 2 9B (Free tier)',
                'meta-llama/llama-3-8b-instruct:free' => 'Llama 3 8B (Free tier)'
            );

            $available_model = null;
            $test_results = array();

            foreach ($test_models as $model => $description) {
                $test_result = $this->test_specific_model($api_key, $model);
                $test_results[$model] = $test_result;

                if ($test_result['success'] && !$available_model) {
                    $available_model = $model;
                    break;
                }
            }

            if ($available_model) {
                // Update the plugin setting to use the working model
                if (function_exists('update_option')) {
                    update_option('twss_openrouter_model', $available_model);
                }

                $message = "✅ OpenRouter API key is valid!\n\n";
                $message .= "📊 Account Information:\n";
                $message .= "• Type: " . ($is_free_tier ? 'Free Tier' : 'Paid Account') . "\n";
                $message .= "• Usage: $" . number_format($usage, 4) . "\n";
                if ($limit_remaining !== null) {
                    $message .= "• Remaining: $" . number_format($limit_remaining, 4) . "\n";
                }
                $message .= "\n✅ Working Model Found:\n";
                $message .= "• " . $test_models[$available_model] . "\n";
                $message .= "• Plugin automatically configured to use this model\n\n";
                $message .= "🎯 Ready for AI-powered security scanning!";

                return array(
                    'success' => true,
                    'message' => $message,
                    'available_model' => $available_model,
                    'account_info' => $account_info
                );
            } else {
                $message = "⚠️ API key is valid but no models are available.\n\n";
                $message .= "📊 Account Information:\n";
                $message .= "• Type: " . ($is_free_tier ? 'Free Tier' : 'Paid Account') . "\n";
                $message .= "• Usage: $" . number_format($usage, 4) . "\n";

                if ($is_free_tier && $usage == 0) {
                    $message .= "\n🎯 Free Tier Account Issues:\n";
                    $message .= "• Free tier may require small credits (even for 'free' models)\n";
                    $message .= "• Account verification may be needed\n";
                    $message .= "• Regional restrictions may apply\n\n";
                    $message .= "💡 Recommended Solutions:\n";
                    $message .= "1. Add $1-2 in credits to your OpenRouter account\n";
                    $message .= "2. Verify your account email and phone number\n";
                    $message .= "3. Try using OpenAI or Google Gemini APIs directly\n\n";
                    $message .= "🔗 Add credits at: https://openrouter.ai/credits";
                } else {
                    $message .= "\n� Model Availability Issues:\n";
                    $message .= "Your account has credits but no models are accessible.\n";
                    $message .= "This commonly occurs due to:\n\n";
                    $message .= "• Regional restrictions on model access\n";
                    $message .= "• Account verification requirements\n";
                    $message .= "• Temporary provider outages\n\n";
                    $message .= "💡 Recommended Solutions:\n";
                    $message .= "1. Verify your account at https://openrouter.ai/account\n";
                    $message .= "2. Contact OpenRouter support about regional access\n";
                    $message .= "3. Use OpenAI API directly (more reliable)\n";
                    $message .= "4. Use Google Gemini API as alternative\n\n";
                    $message .= "🔧 Quick Fix: Configure OpenAI or Gemini instead";
                }

                return array(
                    'success' => false,
                    'message' => $message,
                    'test_results' => $test_results,
                    'account_info' => $account_info
                );
            }
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => 'Error testing API: ' . $e->getMessage()
            );
        }
    }

    /**
     * Test a specific OpenRouter model
     *
     * @since    1.0.30
     * @param    string    $api_key    The API key
     * @param    string    $model      The model to test
     * @return   array                 Test result
     */
    private function test_specific_model($api_key, $model)
    {
        try {
            $data = array(
                'model' => $model,
                'messages' => array(
                    array(
                        'role' => 'user',
                        'content' => 'Test'
                    )
                ),
                'max_tokens' => 3
            );

            $site_url = function_exists('get_site_url') ? get_site_url() : 'http://localhost';
            $site_name = function_exists('get_bloginfo') ? get_bloginfo('name') : 'WordPress Site';

            $headers = array(
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key,
                'HTTP-Referer: ' . $site_url,
                'X-Title: ' . $site_name . ' - Security Scanner Test'
            );

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'https://openrouter.ai/api/v1/chat/completions');
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_TIMEOUT, 10);

            $response = curl_exec($curl);
            $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $error = curl_error($curl);
            curl_close($curl);

            if ($error) {
                return array(
                    'success' => false,
                    'error' => $error
                );
            }

            $response_data = json_decode($response, true);

            if ($status_code === 200 && isset($response_data['choices'][0]['message']['content'])) {
                return array(
                    'success' => true,
                    'response' => $response_data['choices'][0]['message']['content']
                );
            } else {
                $error_message = 'Unknown error';
                if (isset($response_data['error']['message'])) {
                    $error_message = $response_data['error']['message'];
                }

                return array(
                    'success' => false,
                    'error' => $error_message,
                    'status_code' => $status_code
                );
            }
        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Test Groq API key and return available models
     *
     * @since    1.0.31
     * @param    string    $api_key    The Groq API key to test
     * @return   array                 Success status, message, and available models
     */
    public function test_groq_api_key($api_key)
    {
        try {
            // Test with a simple model list request
            $headers = array(
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key
            );

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'https://api.groq.com/openai/v1/models');
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_TIMEOUT, 10);

            $response = curl_exec($curl);
            $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $error = curl_error($curl);
            curl_close($curl);

            if ($error) {
                return array(
                    'success' => false,
                    'message' => 'Connection error: ' . $error
                );
            }

            if ($status_code !== 200) {
                return array(
                    'success' => false,
                    'message' => 'Invalid API key or connection failed'
                );
            }

            $response_data = json_decode($response, true);

            if (!isset($response_data['data']) || !is_array($response_data['data'])) {
                return array(
                    'success' => false,
                    'message' => 'Invalid response from Groq API'
                );
            }

            $models = $response_data['data'];
            $available_models = array();

            // Preferred models in order
            $preferred_models = array(
                'llama-3.3-70b-versatile' => 'Llama 3.3 70B (Best performance)',
                'llama-3.1-70b-versatile' => 'Llama 3.1 70B (High quality)',
                'gemma2-9b-it' => 'Gemma 2 9B (Fast and efficient)',
                'llama-3.1-8b-instant' => 'Llama 3.1 8B (Ultra fast)'
            );

            $best_model = null;

            // Find available models
            foreach ($models as $model) {
                $model_id = $model['id'];
                if (isset($preferred_models[$model_id])) {
                    $available_models[$model_id] = $preferred_models[$model_id];
                    if (!$best_model) {
                        $best_model = $model_id;
                    }
                }
            }

            if ($best_model) {
                // Test the best model with a simple request
                $test_result = $this->test_groq_model($api_key, $best_model);

                if ($test_result['success']) {
                    // Update plugin setting to use the working model
                    if (function_exists('update_option')) {
                        update_option('twss_groq_model', $best_model);
                    }

                    $message = "✅ Groq API key is working perfectly!\n\n";
                    $message .= "🚀 Ultra-Fast AI Analysis Available:\n";
                    $message .= "• Best Model: " . $preferred_models[$best_model] . "\n";
                    $message .= "• Speed: Extremely fast inference (< 1 second)\n";
                    $message .= "• Quality: High-quality malware detection\n\n";

                    if (count($available_models) > 1) {
                        $message .= "📋 Other Available Models:\n";
                        foreach ($available_models as $model_id => $description) {
                            if ($model_id !== $best_model) {
                                $message .= "• " . $description . "\n";
                            }
                        }
                        $message .= "\n";
                    }

                    $message .= "🎯 Ready for lightning-fast AI security scanning!";

                    return array(
                        'success' => true,
                        'message' => $message,
                        'best_model' => $best_model,
                        'available_models' => $available_models,
                        'total_models' => count($models)
                    );
                } else {
                    return array(
                        'success' => false,
                        'message' => 'API key valid but model test failed: ' . $test_result['error']
                    );
                }
            } else {
                return array(
                    'success' => false,
                    'message' => 'API key valid but no preferred models available. Found ' . count($models) . ' models total.'
                );
            }
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => 'Error testing Groq API: ' . $e->getMessage()
            );
        }
    }

    /**
     * Test a specific Groq model
     *
     * @since    1.0.31
     * @param    string    $api_key    The API key
     * @param    string    $model      The model to test
     * @return   array                 Test result
     */
    private function test_groq_model($api_key, $model)
    {
        try {
            $data = array(
                'model' => $model,
                'messages' => array(
                    array(
                        'role' => 'user',
                        'content' => 'Test'
                    )
                ),
                'max_tokens' => 3
            );

            $headers = array(
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key
            );

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'https://api.groq.com/openai/v1/chat/completions');
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_TIMEOUT, 10);

            $response = curl_exec($curl);
            $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $error = curl_error($curl);
            curl_close($curl);

            if ($error) {
                return array(
                    'success' => false,
                    'error' => $error
                );
            }

            $response_data = json_decode($response, true);

            if ($status_code === 200 && isset($response_data['choices'][0]['message']['content'])) {
                return array(
                    'success' => true,
                    'response' => $response_data['choices'][0]['message']['content']
                );
            } else {
                $error_message = 'Unknown error';
                if (isset($response_data['error']['message'])) {
                    $error_message = $response_data['error']['message'];
                }

                return array(
                    'success' => false,
                    'error' => $error_message,
                    'status_code' => $status_code
                );
            }
        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Check if any AI provider is available
     *
     * @since    1.0.2
     * @return   boolean   True if any AI provider is configured
     */
    public function is_ai_available()
    {
        $openai_api_key = get_option('twss_openai_api_key', '');
        $gemini_api_key = get_option('twss_gemini_api_key', '');
        $openrouter_api_key = get_option('twss_openrouter_api_key', '');

        return !empty($openai_api_key) || !empty($gemini_api_key) || !empty($openrouter_api_key);
    }

    /**
     * Get available AI providers
     *
     * @since    1.0.2
     * @return   array     List of available providers
     */
    public function get_available_providers()
    {
        $providers = array();

        $openai_api_key = get_option('twss_openai_api_key', '');
        if (!empty($openai_api_key)) {
            $providers[] = 'openai';
        }

        $gemini_api_key = get_option('twss_gemini_api_key', '');
        if (!empty($gemini_api_key)) {
            $providers[] = 'gemini';
        }

        $openrouter_api_key = get_option('twss_openrouter_api_key', '');
        if (!empty($openrouter_api_key)) {
            $providers[] = 'openrouter';
        }

        return $providers;
    }

    /**
     * Get available OpenRouter models
     *
     * @since    1.0.29
     * @return   array     List of available OpenRouter models
     */
    public function get_openrouter_models()
    {
        return array(
            // Free models (verified working from OpenRouter API)
            'qwen/qwen3-235b-a22b-07-25:free' => array(
                'name' => 'Qwen 3 235B A22B (Free)',
                'description' => 'Alibaba\'s powerful multilingual model with 262K context',
                'cost' => 'Free',
                'context' => '262k tokens'
            ),
            'google/gemma-3n-e2b-it:free' => array(
                'name' => 'Gemma 3N 2B IT (Free)',
                'description' => 'Google\'s efficient multimodal model',
                'cost' => 'Free',
                'context' => '8k tokens'
            ),
            'moonshotai/kimi-k2:free' => array(
                'name' => 'Kimi K2 (Free)',
                'description' => 'MoE model optimized for agentic capabilities and tool use',
                'cost' => 'Free',
                'context' => '65k tokens'
            ),
            'tencent/hunyuan-a13b-instruct:free' => array(
                'name' => 'Hunyuan A13B Instruct (Free)',
                'description' => 'Tencent\'s MoE model with reasoning capabilities',
                'cost' => 'Free',
                'context' => '32k tokens'
            ),
            'cognitivecomputations/dolphin-mistral-24b-venice-edition:free' => array(
                'name' => 'Venice Uncensored (Free)',
                'description' => 'Uncensored fine-tuned Mistral model for flexible analysis',
                'cost' => 'Free',
                'context' => '32k tokens'
            ),
            'microsoft/wizardlm-2-8x22b:free' => array(
                'name' => 'WizardLM-2 8x22B (Free)',
                'description' => 'High-quality reasoning model for security analysis',
                'cost' => 'Free',
                'context' => '65k tokens'
            ),
            'google/gemma-2-9b-it:free' => array(
                'name' => 'Gemma 2 9B IT (Free)',
                'description' => 'Google\'s reliable open model for code analysis',
                'cost' => 'Free',
                'context' => '8k tokens'
            ),
            'meta-llama/llama-3-8b-instruct:free' => array(
                'name' => 'Llama 3 8B Instruct (Free)',
                'description' => 'Meta\'s efficient model for code analysis',
                'cost' => 'Free',
                'context' => '8k tokens'
            ),

            // Paid models (better performance and reliability)
            'openai/gpt-3.5-turbo' => array(
                'name' => 'GPT-3.5 Turbo',
                'description' => 'OpenAI\'s reliable model with excellent security analysis',
                'cost' => '$0.50/1M input, $1.50/1M output',
                'context' => '128k tokens'
            ),
            'openai/gpt-4-turbo' => array(
                'name' => 'GPT-4 Turbo',
                'description' => 'OpenAI\'s most capable model',
                'cost' => '$10/1M input, $30/1M output',
                'context' => '128k tokens'
            ),
            'anthropic/claude-3-haiku' => array(
                'name' => 'Claude 3 Haiku',
                'description' => 'Fast and accurate, excellent for code analysis',
                'cost' => '$0.25/1M input, $1.25/1M output',
                'context' => '200k tokens'
            ),
            'anthropic/claude-3-5-sonnet' => array(
                'name' => 'Claude 3.5 Sonnet',
                'description' => 'Top-tier performance for complex security analysis',
                'cost' => '$3/1M input, $15/1M output',
                'context' => '200k tokens'
            ),
            'google/gemini-pro-1.5' => array(
                'name' => 'Gemini Pro 1.5',
                'description' => 'Google\'s advanced model with large context',
                'cost' => '$2.50/1M input, $10/1M output',
                'context' => '2M tokens'
            )
        );
    }

    /**
     * Test OpenRouter API with specific model
     *
     * @since    1.0.29
     * @param    string    $api_key    The OpenRouter API key to test
     * @param    string    $model      The model to test (optional)
     * @return   array                 Success status and message
     */
    public function test_openrouter_api_with_model($api_key, $model = 'openai/gpt-3.5-turbo')
    {
        try {
            $data = array(
                'model' => $model,
                'messages' => array(
                    array(
                        'role' => 'user',
                        'content' => 'Say "API connection successful with ' . $model . '" if you can read this message.'
                    )
                ),
                'max_tokens' => 20
            );

            // Get the actual website URL for tracking
            $site_url = function_exists('get_site_url') ? get_site_url() : 'http://localhost';
            $site_name = function_exists('get_bloginfo') ? get_bloginfo('name') : 'WordPress Site';

            $headers = array(
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key,
                'HTTP-Referer: ' . $site_url,
                'X-Title: ' . $site_name . ' - Themewire Security Scanner Test'
            );

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'https://openrouter.ai/api/v1/chat/completions');
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_TIMEOUT, 15);
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

            $response = curl_exec($curl);
            $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $err = curl_error($curl);
            curl_close($curl);

            if ($err) {
                return array(
                    'success' => false,
                    'message' => 'cURL Error: ' . $err
                );
            }

            if ($status !== 200) {
                $error_data = json_decode($response, true);
                if (isset($error_data['error'])) {
                    $error_msg = $error_data['error']['message'] ?? 'Unknown API error';

                    // Handle specific model errors
                    if (strpos($error_msg, 'model') !== false) {
                        return array(
                            'success' => false,
                            'message' => 'Model "' . $model . '" is not available or accessible with your API key. ' . $error_msg
                        );
                    }

                    return array(
                        'success' => false,
                        'message' => $error_msg
                    );
                }

                return array(
                    'success' => false,
                    'message' => 'API returned status code ' . $status
                );
            }

            $response_data = json_decode($response, true);
            if (isset($response_data['choices'][0]['message']['content'])) {
                return array(
                    'success' => true,
                    'message' => 'OpenRouter API key is valid and model "' . $model . '" is accessible!',
                    'model_response' => $response_data['choices'][0]['message']['content']
                );
            }

            return array(
                'success' => false,
                'message' => 'Unexpected API response format'
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'message' => $e->getMessage()
            );
        }
    }
}
