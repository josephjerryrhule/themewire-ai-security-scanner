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
     * Initialize AI API clients
     *
     * @since    1.0.0
     */
    private function init_ai_clients()
    {
        $ai_provider = get_option('twss_ai_provider', 'openai');

        if ($ai_provider === 'openai') {
            $api_key = get_option('twss_openai_api_key', '');
            if (!empty($api_key)) {
                // Initialize OpenAI client
                $this->init_openai_client($api_key);
            }
        } else if ($ai_provider === 'gemini') {
            $api_key = get_option('twss_gemini_api_key', '');
            if (!empty($api_key)) {
                // Initialize Gemini client
                $this->init_gemini_client($api_key);
            }
        } else if ($ai_provider === 'openrouter') {
            $api_key = get_option('twss_openrouter_api_key', '');
            if (!empty($api_key)) {
                // Initialize OpenRouter client
                $this->init_openrouter_client($api_key);
            }
        }

        // If no API key is provided, we'll use the fallback method
    }

    /**
     * Initialize AI clients with OAuth support
     *
     * @since    1.0.2
     */
    private function init_ai_clients_with_oauth()
    {
        $ai_provider = get_option('twss_ai_provider', 'openai');

        if ($ai_provider === 'openai') {
            $api_key = get_option('twss_openai_api_key', '');
            $oauth_token = get_option('twss_openai_oauth_token', '');

            if (!empty($api_key)) {
                $this->init_openai_client($api_key);
            } else if (!empty($oauth_token)) {
                $this->init_openai_oauth_client($oauth_token);
            }
        } else if ($ai_provider === 'gemini') {
            $api_key = get_option('twss_gemini_api_key', '');
            $oauth_token = get_option('twss_gemini_oauth_token', '');

            if (!empty($api_key)) {
                $this->init_gemini_client($api_key);
            } else if (!empty($oauth_token)) {
                $this->init_gemini_oauth_client($oauth_token);
            }
        }
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
     * Initialize OpenAI OAuth client
     *
     * @since    1.0.2
     * @param    string    $oauth_token    OAuth token
     */
    private function init_openai_oauth_client($oauth_token)
    {
        $this->openai_client = new stdClass();
        $this->openai_client->oauth_token = $oauth_token;
        $this->openai_client->is_oauth = true;
    }

    /**
     * Initialize Gemini OAuth client
     *
     * @since    1.0.2
     * @param    string    $oauth_token    OAuth token
     */
    private function init_gemini_oauth_client($oauth_token)
    {
        $this->gemini_client = new stdClass();
        $this->gemini_client->oauth_token = $oauth_token;
        $this->gemini_client->is_oauth = true;
    }

    /**
     * Queue a file for AI analysis
     *
     * @since    1.0.0
     * @param    int       $scan_id    The scan ID
     * @param    string    $file_path  Path to the file
     */
    public function queue_file_for_analysis($scan_id, $file_path)
    {
        // Only queue files that exist and are readable
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }

        if (!isset($this->queued_files[$scan_id])) {
            $this->queued_files[$scan_id] = array();
        }

        $this->queued_files[$scan_id][] = $file_path;
        return true;
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
     * Analyze a file using AI
     *
     * @since    1.0.0
     * @param    string    $file_path    Path to the file
     * @return   array     Analysis result
     */
    public function analyze_file($file_path)
    {
        // Validate file exists and is readable before analysis
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return array(
                'is_malicious' => false,
                'confidence' => 0,
                'indicators' => array(),
                'error' => 'File not found or not readable'
            );
        }

        $file_content = file_get_contents($file_path);
        if ($file_content === false) {
            return array(
                'is_malicious' => false,
                'confidence' => 0,
                'indicators' => array(),
                'error' => 'Failed to read file content'
            );
        }

        $file_extension = pathinfo($file_path, PATHINFO_EXTENSION);

        // Limit file content to prevent API limit issues
        $file_content = $this->truncate_file_content($file_content, 10000);

        $ai_provider = get_option('twss_ai_provider', 'openai');

        if ($ai_provider === 'openai' && $this->openai_client) {
            return $this->analyze_with_openai($file_path, $file_content, $file_extension);
        } else if ($ai_provider === 'gemini' && $this->gemini_client) {
            return $this->analyze_with_gemini($file_path, $file_content, $file_extension);
        } else if ($ai_provider === 'openrouter' && $this->openrouter_client) {
            return $this->analyze_with_openrouter($file_path, $file_content, $file_extension);
        } else {
            // Fallback to simple analysis
            return $this->analyze_with_fallback($file_path, $file_content, $file_extension);
        }
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
        if (preg_match('/\/(tmp|temp|cache|log)\/.*\.(php|js|html)$/i', $file_path)) {
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
        if (preg_match('/file_get_contents\s*\(\s*["\']https?:\/\//', $content)) {
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
            throw new Exception('API request error: ' . $err);
        }

        $response_data = json_decode($response, true);

        if (isset($response_data['choices'][0]['message']['content'])) {
            return $response_data['choices'][0]['message']['content'];
        } else {
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

                // Handle quota exhausted error (429)
                if ($error_code === 429 || $error_status === 'RESOURCE_EXHAUSTED') {
                    // Log sanitized error for admin
                    error_log('Gemini API Quota Exhausted - Falling back to pattern-based analysis');

                    // Return user-friendly error message
                    throw new Exception('AI analysis temporarily unavailable due to quota limits. Using pattern-based analysis instead.');
                }

                // Handle rate limiting
                if ($error_code === 429) {
                    error_log('Gemini API Rate Limited - Retrying with pattern analysis');
                    throw new Exception('AI service rate limited. Falling back to pattern analysis.');
                }

                // Handle other API errors with sanitized messages
                error_log("Gemini API Error [{$error_code}]: {$error_message}");
                throw new Exception("AI analysis service error. Using pattern-based detection instead.");
            }

            // Log raw response for debugging (but sanitize in production)
            error_log('Gemini API: Invalid response structure received');
            throw new Exception('AI service returned invalid response. Using fallback analysis.');
        }
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

        $headers = array(
            'Content-Type: application/json',
            'Authorization: Bearer ' . $api_key,
            'HTTP-Referer: https://yourdomain.com', // Replace with your actual domain
            'X-Title: WordPress Security Scanner'
        );

        $data = array(
            'model' => 'meta-llama/llama-3.1-8b-instruct:free', // Using a free model, can be configured
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
                
                // Handle quota/credit exhausted errors
                if ($error_code === 429 || strpos($error_message, 'quota') !== false || strpos($error_message, 'credit') !== false) {
                    error_log('OpenRouter API Quota/Credits Exhausted - Falling back to pattern-based analysis');
                    throw new Exception('AI analysis temporarily unavailable due to quota limits. Using pattern-based analysis instead.');
                }
                
                // Handle rate limiting
                if ($error_code === 429) {
                    error_log('OpenRouter API Rate Limited - Retrying with pattern analysis');
                    throw new Exception('AI service rate limited. Falling back to pattern analysis.');
                }
                
                // Handle other API errors with sanitized messages
                error_log("OpenRouter API Error [{$error_code}]: {$error_message}");
                throw new Exception("AI analysis service error. Using pattern-based detection instead.");
            }
            
            // Log for debugging
            error_log('OpenRouter API: Invalid response structure received');
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
        $prompt .= "SUGGESTED_ACTION: [quarantine/delete/fix/monitor/none]\n\n";

        $prompt .= "IMPORTANT: Base your analysis on concrete evidence. If the file appears to be minified but legitimate, or if obfuscation serves a legitimate purpose (like code protection), do not flag it as malicious.";

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

        return $result;
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
     * Check if any AI provider is available
     *
     * @since    1.0.2
     * @return   boolean   True if any AI provider is configured
     */
    public function is_ai_available()
    {
        $openai_api_key = get_option('twss_openai_api_key', '');
        $openai_oauth = get_option('twss_openai_oauth_token', '');
        $gemini_api_key = get_option('twss_gemini_api_key', '');
        $gemini_oauth = get_option('twss_gemini_oauth_token', '');
        $openrouter_api_key = get_option('twss_openrouter_api_key', '');

        return !empty($openai_api_key) || !empty($openai_oauth) || !empty($gemini_api_key) || !empty($gemini_oauth) || !empty($openrouter_api_key);
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
        $openai_oauth = get_option('twss_openai_oauth_token', '');
        if (!empty($openai_api_key) || !empty($openai_oauth)) {
            $providers[] = 'openai';
        }

        $gemini_api_key = get_option('twss_gemini_api_key', '');
        $gemini_oauth = get_option('twss_gemini_oauth_token', '');
        if (!empty($gemini_api_key) || !empty($gemini_oauth)) {
            $providers[] = 'gemini';
        }

        $openrouter_api_key = get_option('twss_openrouter_api_key', '');
        if (!empty($openrouter_api_key)) {
            $providers[] = 'openrouter';
        }

        return $providers;
    }

    /**
     * Get OpenAI OAuth authorization URL
     *
     * @since    1.0.2
     * @return   string    Authorization URL
     */
    public function get_openai_oauth_url()
    {
        $client_id = get_option('twss_openai_client_id', '');

        if (empty($client_id)) {
            return false; // OAuth not properly configured
        }

        $redirect_uri = admin_url('admin.php?page=themewire-security-oauth-callback');
        $state = wp_create_nonce('openai_oauth_state');

        $params = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'api.read',
            'state' => $state
        );

        return 'https://platform.openai.com/oauth/authorize?' . http_build_query($params);
    }

    /**
     * Get Google OAuth authorization URL for Gemini
     *
     * @since    1.0.2
     * @return   string    Authorization URL
     */
    public function get_gemini_oauth_url()
    {
        $client_id = get_option('twss_gemini_client_id', '');

        if (empty($client_id)) {
            return false; // OAuth not properly configured
        }

        $redirect_uri = admin_url('admin.php?page=themewire-security-oauth-callback');
        $state = wp_create_nonce('gemini_oauth_state');

        $params = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'https://www.googleapis.com/auth/generative-language',
            'access_type' => 'offline',
            'state' => $state
        );

        return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
    }
}
