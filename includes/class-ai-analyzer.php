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
        if (!isset($this->queued_files[$scan_id])) {
            $this->queued_files[$scan_id] = array();
        }

        $this->queued_files[$scan_id][] = $file_path;
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
        $file_content = file_get_contents($file_path);
        $file_extension = pathinfo($file_path, PATHINFO_EXTENSION);

        // Limit file content to prevent API limit issues
        $file_content = $this->truncate_file_content($file_content, 10000);

        $ai_provider = get_option('twss_ai_provider', 'openai');

        if ($ai_provider === 'openai' && $this->openai_client) {
            return $this->analyze_with_openai($file_path, $file_content, $file_extension);
        } else if ($ai_provider === 'gemini' && $this->gemini_client) {
            return $this->analyze_with_gemini($file_path, $file_content, $file_extension);
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
     * Analyze file with fallback method (no AI API)
     *
     * @since    1.0.0
     * @param    string    $file_path       File path
     * @param    string    $file_content    File content
     * @param    string    $file_extension  File extension
     * @return   array     Analysis result
     */
    private function analyze_with_fallback($file_path, $file_content, $file_extension)
    {
        $suspicious_patterns = array(
            // PHP patterns
            'eval(' => 'Found eval() function that can execute arbitrary code',
            'base64_decode(' => 'Found base64_decode() which is often used to hide malicious code',
            'system(' => 'Found system() function that can execute system commands',
            'exec(' => 'Found exec() function that can execute system commands',
            'passthru(' => 'Found passthru() function that can execute system commands',
            'shell_exec(' => 'Found shell_exec() function that can execute system commands',
            'assert(' => 'Found assert() function that can be used for code execution',
            'preg_replace' => 'Found preg_replace() which can execute code with /e modifier',
            'create_function(' => 'Found create_function() which can execute arbitrary code',
            'include($_' => 'Found dynamic include based on user input',
            'require($_' => 'Found dynamic require based on user input',
            'include_once($_' => 'Found dynamic include_once based on user input',
            'require_once($_' => 'Found dynamic require_once based on user input',
            '$_REQUEST' => 'Found direct usage of $_REQUEST superglobal',
            '$_GET' => 'Found direct usage of $_GET superglobal',
            '$_POST' => 'Found direct usage of $_POST superglobal',

            // JavaScript patterns
            'eval(' => 'Found eval() function that can execute arbitrary code',
            'document.write(' => 'Found document.write() which can be used in XSS attacks',
            'fromCharCode(' => 'Found String.fromCharCode() which can be used to obfuscate strings',
            'unescape(' => 'Found unescape() function which can be used to obfuscate code',
        );

        $is_malware = false;
        $explanation = '';
        $suggested_fix = '';

        foreach ($suspicious_patterns as $pattern => $reason) {
            if (strpos($file_content, $pattern) !== false) {
                $is_malware = true;
                $explanation = $reason;
                break;
            }
        }

        // If it's a PHP file in the uploads directory, it's almost always malicious
        if ($file_extension === 'php' && strpos($file_path, 'wp-content/uploads') !== false) {
            $is_malware = true;
            $explanation = 'PHP file found in uploads directory, which is unusual and potentially malicious';
            $suggested_fix = 'quarantine';
        }

        // Check for obfuscated code
        if ($this->seems_obfuscated($file_content)) {
            $is_malware = true;
            $explanation = 'Contains obfuscated code which is a strong indicator of malicious intent';
            $suggested_fix = 'quarantine';
        }

        return array(
            'is_malware' => $is_malware,
            'explanation' => $explanation,
            'suggested_fix' => $suggested_fix
        );
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
            // Log the error for debugging
            error_log('Gemini API Error: ' . print_r($response_data, true));
            throw new Exception('Invalid API response from Gemini');
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
        $prompt = "Analyze the following " . strtoupper($file_extension) . " file for security issues, malware, or suspicious code:\n\n";
        $prompt .= "FILE PATH: " . $file_path . "\n\n";
        $prompt .= "FILE CONTENT:\n```" . $file_extension . "\n" . $file_content . "\n```\n\n";

        $prompt .= "Please determine if this file contains malware or security vulnerabilities. Focus on:\n";
        $prompt .= "1. Code obfuscation techniques\n";
        $prompt .= "2. Backdoors or unauthorized access mechanisms\n";
        $prompt .= "3. Malicious redirects\n";
        $prompt .= "4. Exploit code\n";
        $prompt .= "5. Suspicious functions (eval, base64_decode, etc.)\n\n";

        $prompt .= "Answer in this format:\n";
        $prompt .= "MALICIOUS: [Yes/No]\n";
        $prompt .= "EXPLANATION: [Detailed explanation]\n";
        $prompt .= "SUGGESTED FIX: [quarantine/delete/fix/none]\n";

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
            'explanation' => '',
            'suggested_fix' => ''
        );

        // Look for clear indicators in the response
        if (preg_match('/MALICIOUS:\s*(Yes|No)/i', $response, $matches)) {
            $result['is_malware'] = (strtolower($matches[1]) === 'yes');
        } else if (preg_match('/malware|malicious|suspicious|vulnerability|exploit|backdoor|security risk/i', $response)) {
            $result['is_malware'] = true;
        }

        // Extract explanation
        if (preg_match('/EXPLANATION:\s*(.+?)(?=SUGGESTED FIX:|$)/is', $response, $matches)) {
            $result['explanation'] = trim($matches[1]);
        } else {
            $result['explanation'] = $response;
        }

        // Try to extract suggested fix if available
        if (preg_match('/SUGGESTED FIX:\s*(quarantine|delete|fix|none)/i', $response, $matches)) {
            $result['suggested_fix'] = strtolower($matches[1]);
        } else if (strpos(strtolower($response), 'quarantine') !== false) {
            $result['suggested_fix'] = 'quarantine';
        } else if (strpos(strtolower($response), 'delete') !== false) {
            $result['suggested_fix'] = 'delete';
        } else if (strpos(strtolower($response), 'fix') !== false) {
            $result['suggested_fix'] = 'fix';
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

        return !empty($openai_api_key) || !empty($openai_oauth) || !empty($gemini_api_key) || !empty($gemini_oauth);
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
        $client_id = 'your-openai-app-client-id'; // This would be configured
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
        $client_id = 'your-google-app-client-id.googleusercontent.com'; // This would be configured
        $redirect_uri = admin_url('admin.php?page=themewire-security-oauth-callback');
        $state = wp_create_nonce('gemini_oauth_state');

        $params = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'https://www.googleapis.com/auth/generative-language',
            'state' => $state
        );

        return 'https://accounts.google.com/oauth/authorize?' . http_build_query($params);
    }
}
