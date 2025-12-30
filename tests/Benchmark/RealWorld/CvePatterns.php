<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\RealWorld;

/**
 * Real-World CVE Patterns
 *
 * Vulnerability patterns based on actual CVEs.
 * These represent real attacks that have occurred in the wild.
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class CvePatterns
{
    // =========================================================================
    // CVE-2012-1823: PHP CGI Argument Injection
    // Affected: PHP before 5.3.12/5.4.2 in CGI mode
    // =========================================================================

    /**
     * Pattern: Query string passed to PHP CLI arguments
     * Impact: Remote code execution
     */
    public function cgiArgumentInjection(): void
    {
        // Original: ?-s (shows source) or ?-d+allow_url_include=1+-d+auto_prepend_file=...
        $args = $_SERVER['QUERY_STRING'];
        // CGI would interpret these as PHP CLI arguments
    }

    // =========================================================================
    // CVE-2016-5385: HTTPoxy
    // Affected: PHP, Python, Go applications behind CGI
    // =========================================================================

    /**
     * Pattern: Trusting Proxy header from client
     * Impact: SSRF, credential theft
     */
    public function httpoxyVulnerable(): string
    {
        // Attacker sends: Proxy: attacker.com
        // CGI sets HTTP_PROXY from this header
        $proxy = getenv('HTTP_PROXY'); // Attacker-controlled
        $ch = curl_init('https://api.internal.com/secrets');
        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, $proxy);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return (string) curl_exec($ch);
    }

    // =========================================================================
    // CVE-2019-11043: PHP-FPM RCE
    // Affected: PHP 7.1.x < 7.1.33, 7.2.x < 7.2.24, 7.3.x < 7.3.11
    // =========================================================================

    /**
     * Pattern: Nginx fastcgi_split_path_info with newline
     * Impact: Remote code execution via buffer underflow
     *
     * Nginx config pattern:
     * location ~ [^/]\.php(/|$) {
     *     fastcgi_split_path_info ^(.+?\.php)(/.*)$;
     * }
     */
    public function phpFpmPathInfo(): void
    {
        // Attack: /index.php/path%0Ainfo
        $pathInfo = $_SERVER['PATH_INFO'] ?? '';
        // PHP-FPM buffer underflow when PATH_INFO contains newline
    }

    // =========================================================================
    // CVE-2021-21707: PHP XML External Entity Injection
    // Affected: libxml configurations
    // =========================================================================

    /**
     * Pattern: XXE in XML parsing
     * Impact: File disclosure, SSRF
     */
    public function xxeFileDisclosure(): void
    {
        $xml = $_POST['xml'];
        // Malicious XML:
        // <?xml version="1.0"?>
        // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        // <data>&xxe;</data>

        $doc = new \DOMDocument();
        $doc->loadXML($xml, LIBXML_NOENT); // LIBXML_NOENT enables entity substitution
    }

    // =========================================================================
    // CVE-2017-5638: Struts2 Content-Type RCE (PHP equivalent pattern)
    // Pattern: OGNL injection via header parsing
    // =========================================================================

    /**
     * Pattern: User input in error message with expression evaluation
     * Impact: Remote code execution
     */
    public function headerExpressionInjection(): void
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        // Bad pattern: evaluating user input in error context
        if (!preg_match('/^application\/json/', $contentType)) {
            eval('$error = "Invalid content type: ' . $contentType . '";');
        }
    }

    // =========================================================================
    // CVE-2018-15133: Laravel Unserialize RCE
    // Affected: Laravel < 5.6.30
    // =========================================================================

    /**
     * Pattern: Deserialization of encrypted cookie without integrity check
     * Impact: Remote code execution via POP chain
     */
    public function laravelCookieDeserialize(): void
    {
        $cookie = $_COOKIE['laravel_session'];
        $decoded = base64_decode($cookie);
        // In vulnerable versions, decryption + deserialization without MAC verification
        $data = unserialize($decoded);
    }

    // =========================================================================
    // CVE-2015-4852: Java Deserialize (PHP equivalent)
    // Pattern: Commons Collections gadget chain
    // =========================================================================

    /**
     * Pattern: Magic methods triggered during deserialization
     * Impact: Remote code execution
     */
    public function magicMethodGadget(): void
    {
        // Class with dangerous __wakeup or __destruct
        $data = $_POST['serialized'];
        $obj = unserialize($data);
        // If $obj contains: VulnerableClass with __destruct calling system()
    }

    // =========================================================================
    // CVE-2020-8840: Jackson Polymorphic Type RCE (PHP equivalent)
    // Pattern: Type confusion in polymorphic deserialization
    // =========================================================================

    /**
     * Pattern: JSON type coercion leading to arbitrary object creation
     * Impact: Remote code execution
     */
    public function polymorphicTypeConfusion(): void
    {
        $json = $_POST['data'];
        $data = json_decode($json, false);

        // Attacker sends: {"@type": "VulnerableClass", "cmd": "whoami"}
        if (isset($data->{'@type'})) {
            $class = $data->{'@type'};
            $obj = new $class(); // Arbitrary class instantiation
            foreach ($data as $prop => $value) {
                if ($prop !== '@type') {
                    $obj->$prop = $value;
                }
            }
        }
    }

    // =========================================================================
    // CVE-2019-6340: Drupal REST RCE
    // Affected: Drupal 8.x before 8.5.11, 8.6.x before 8.6.10
    // =========================================================================

    /**
     * Pattern: Unsafe deserialization in REST endpoint
     * Impact: Remote code execution
     */
    public function restDeserialize(): void
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $body = file_get_contents('php://input');

        if (strpos($contentType, 'hal+json') !== false) {
            $data = json_decode($body, true);
            if (isset($data['link']['value'])) {
                // Vulnerable: user controls serialized data
                $link = unserialize($data['link']['value']);
            }
        }
    }

    // =========================================================================
    // CVE-2021-3129: Laravel Ignition RCE
    // Affected: Laravel Ignition < 2.5.2
    // =========================================================================

    /**
     * Pattern: Arbitrary file write via log manipulation
     * Impact: Remote code execution
     */
    public function logFileManipulation(): void
    {
        $solution = json_decode($_POST['solution'], true);

        // Vulnerable pattern: write to log based on user input
        if (isset($solution['_solution']) && isset($solution['_parameters'])) {
            $logFile = $solution['_parameters']['viewFile'];
            $content = $solution['_parameters']['contents'];
            // Attacker writes PHP to a .php file
            file_put_contents($logFile, $content);
        }
    }

    // =========================================================================
    // CVE-2023-33568: PHPFusion SQL Injection
    // Pattern: Improper sanitization bypass
    // =========================================================================

    /**
     * Pattern: stripslashes defeating addslashes
     * Impact: SQL injection
     */
    public function sanitizationBypass(): void
    {
        $input = $_GET['search'];
        $escaped = addslashes($input);
        // Later processing removes slashes
        $clean = stripslashes($escaped);
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM products WHERE name LIKE '%{$clean}%'");
    }

    // =========================================================================
    // CVE-2022-31813: Apache mod_proxy X-Forwarded-For bypass
    // Pattern: Header trust without validation
    // =========================================================================

    /**
     * Pattern: Trusting X-Forwarded-For for access control
     * Impact: Access control bypass
     */
    public function forwardedHeaderTrust(): bool
    {
        $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR']
            ?? $_SERVER['HTTP_X_REAL_IP']
            ?? $_SERVER['REMOTE_ADDR'];

        // First IP in chain
        $ip = explode(',', $clientIp)[0];

        // Attacker sets: X-Forwarded-For: 10.0.0.1
        $allowed = ['10.0.0.0/8', '192.168.0.0/16'];
        return $this->ipInRange($ip, $allowed);
    }

    private function ipInRange(string $ip, array $ranges): bool
    {
        // Simplified check
        return str_starts_with($ip, '10.') || str_starts_with($ip, '192.168.');
    }

    // =========================================================================
    // CVE-2021-44228: Log4Shell (PHP equivalent pattern)
    // Pattern: JNDI injection via log message
    // =========================================================================

    /**
     * Pattern: User input in log message triggers lookup
     * Impact: Remote code execution
     */
    public function logLookupInjection(): void
    {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // If logging library supports lookups like ${jndi:ldap://...}
        // PHP doesn't have JNDI, but similar patterns exist with variable interpolation
        error_log("User-Agent: $userAgent");

        // PHP equivalent: eval in log processing
        $this->customLog("Access from: $userAgent");
    }

    private function customLog(string $message): void
    {
        // Bad pattern: variable expansion in log
        $expanded = preg_replace_callback('/\$\{([^}]+)\}/', function ($m) {
            $expr = $m[1];
            if (str_starts_with($expr, 'env:')) {
                return getenv(substr($expr, 4)) ?: '';
            }
            return $m[0];
        }, $message);

        file_put_contents('/var/log/app.log', $expanded . "\n", FILE_APPEND);
    }

    // =========================================================================
    // CVE-2018-1000136: Electron nodeIntegration RCE (web equivalent)
    // Pattern: XSS with elevated privileges
    // =========================================================================

    /**
     * Pattern: XSS in admin context with dangerous functions available
     * Impact: Elevated privilege execution
     */
    public function xssWithPrivileges(): void
    {
        if ($_SESSION['role'] === 'admin') {
            // Admin-only feature with XSS
            $reportName = $_GET['report'];
            echo "<h1>Report: {$reportName}</h1>";

            // XSS payload could call admin-only functions
            // e.g., <script>fetch('/admin/delete-all')</script>
        }
    }

    // =========================================================================
    // CVE-2017-9841: PHPUnit RCE
    // Affected: PHPUnit before 4.8.28 and 5.x before 5.6.3
    // =========================================================================

    /**
     * Pattern: eval-stdin.php accessible via web
     * Impact: Remote code execution
     */
    public function phpunitEvalExposed(): void
    {
        // In vulnerable installations, /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
        // was accessible and would execute any PHP code sent via stdin
        $code = file_get_contents('php://input');
        eval($code);
    }

    // =========================================================================
    // CVE-2020-15148: Yii Framework Deserialization
    // Pattern: Database result deserialization
    // =========================================================================

    /**
     * Pattern: Unserialize data from database
     * Impact: Remote code execution via second-order attack
     */
    public function secondOrderDeserialize(): void
    {
        $pdo = new \PDO('sqlite::memory:');

        // First: attacker stores serialized payload in DB via another endpoint
        // Later: application retrieves and unserializes
        $stmt = $pdo->query("SELECT serialized_data FROM user_settings WHERE user_id = 1");
        $data = $stmt->fetchColumn();

        // Unserialize data that originally came from user
        $settings = unserialize($data);
    }

    // =========================================================================
    // CVE-2022-22965: Spring4Shell (PHP equivalent pattern)
    // Pattern: Class loader manipulation via parameter binding
    // =========================================================================

    /**
     * Pattern: Recursive parameter binding to object properties
     * Impact: Property manipulation, potential RCE
     */
    public function nestedParameterBinding(): void
    {
        $params = $_POST;

        // Vulnerable: bind nested parameters to object
        // class.module.classLoader.resources.context.parent... = payload
        $obj = new TargetClass();
        $this->bindParameters($obj, $params);
    }

    private function bindParameters(object $obj, array $params, string $prefix = ''): void
    {
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                if (property_exists($obj, $key)) {
                    $this->bindParameters($obj->$key, $value, "{$prefix}{$key}.");
                }
            } else {
                if (property_exists($obj, $key)) {
                    $obj->$key = $value;
                }
            }
        }
    }
}

class TargetClass
{
    public object $module;
    public array $settings = [];

    public function __construct()
    {
        $this->module = new \stdClass();
    }
}

/**
 * Simulated vulnerable class for deserialization attacks
 */
class VulnerableGadget
{
    public string $command = '';

    public function __destruct()
    {
        if ($this->command) {
            system($this->command);
        }
    }
}
