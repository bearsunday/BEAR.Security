<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\TruePositives\Level2_Intermediate;

/**
 * Level 2: Intermediate Vulnerabilities
 *
 * Indirect patterns through variables, multiple steps, wrapper functions.
 * Detection difficulty: Medium
 * Expected detection rate: 70-90%
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class IntermediateVulnerabilities
{
    // =========================================================================
    // SQL Injection via Variables
    // =========================================================================

    public function sqlViaVariable(): void
    {
        $userId = $_GET['id'];
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM users WHERE id = " . $userId);
    }

    public function sqlViaMultipleSteps(): void
    {
        $input = $_POST['search'];
        $term = trim($input);
        $query = "SELECT * FROM products WHERE name LIKE '%" . $term . "%'";
    }

    public function sqlViaConcatenatedVariable(): void
    {
        $table = $_GET['table'];
        $column = $_GET['column'];
        $value = $_GET['value'];
        $sql = "SELECT * FROM " . $table . " WHERE " . $column . " = '" . $value . "'";
    }

    public function sqlViaSprintfPartial(): void
    {
        $id = $_GET['id'];
        $query = sprintf("SELECT * FROM users WHERE id = %s", $id);
    }

    public function sqlViaArrayAccess(): void
    {
        $params = $_REQUEST;
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM logs WHERE action = '" . $params['action'] . "'");
    }

    // =========================================================================
    // XSS via Variables and Functions
    // =========================================================================

    public function xssViaVariable(): void
    {
        $name = $_GET['name'];
        echo "<h1>Welcome, " . $name . "</h1>";
    }

    public function xssViaReturnValue(): string
    {
        $msg = $this->getUserInput();
        return "<div>" . $msg . "</div>";
    }

    private function getUserInput(): string
    {
        return $_POST['message'] ?? '';
    }

    public function xssViaArrayLoop(): void
    {
        foreach ($_GET as $key => $value) {
            echo "<input name='$key' value='$value'>";
        }
    }

    public function xssViaImplode(): void
    {
        $items = $_POST['items'];
        echo "<ul><li>" . implode("</li><li>", $items) . "</li></ul>";
    }

    public function xssInJsonContext(): void
    {
        $data = $_GET['callback'];
        echo $data . "(" . json_encode(['status' => 'ok']) . ")";
    }

    // =========================================================================
    // Command Injection via Variables
    // =========================================================================

    public function cmdViaVariable(): void
    {
        $filename = $_GET['file'];
        exec("cat " . $filename);
    }

    public function cmdViaConcatenation(): void
    {
        $host = $_POST['host'];
        $port = $_POST['port'];
        $cmd = "nc " . $host . " " . $port;
        shell_exec($cmd);
    }

    public function cmdViaInterpolation(): void
    {
        $dir = $_GET['dir'];
        system("ls -la $dir");
    }

    public function cmdViaPartialEscape(): void
    {
        $safe = escapeshellarg($_GET['safe']);
        $unsafe = $_GET['unsafe'];
        exec("process $safe --option=$unsafe");
    }

    // =========================================================================
    // Path Traversal via Variables
    // =========================================================================

    public function pathViaVariable(): void
    {
        $page = $_GET['page'];
        $path = "/var/www/templates/" . $page . ".php";
        include($path);
    }

    public function pathViaBasenameBypass(): void
    {
        // basename can be bypassed with null bytes in older PHP
        $file = basename($_GET['file']);
        include("/templates/" . $file);
    }

    public function pathViaExtensionCheck(): void
    {
        $file = $_POST['file'];
        if (pathinfo($file, PATHINFO_EXTENSION) === 'txt') {
            // Can be bypassed: ../../etc/passwd%00.txt
            readfile("/uploads/" . $file);
        }
    }

    // =========================================================================
    // Deserialization via Variables
    // =========================================================================

    public function deserializeViaVariable(): void
    {
        $data = $_COOKIE['session_data'];
        $decoded = base64_decode($data);
        $obj = unserialize($decoded);
    }

    public function deserializeViaFileContents(): void
    {
        $file = "/tmp/cache/" . $_GET['cache_id'];
        $data = file_get_contents($file);
        $result = unserialize($data);
    }

    // =========================================================================
    // Weak Cryptography in Context
    // =========================================================================

    public function weakHashViaVariable(): void
    {
        $password = $_POST['password'];
        $salt = 'static_salt';
        $hash = md5($salt . $password);
    }

    public function weakTokenGeneration(): string
    {
        $userId = $_SESSION['user_id'];
        $time = time();
        return md5($userId . $time);
    }

    public function insecureCompare(): bool
    {
        $userToken = $_GET['token'];
        $storedToken = $this->getStoredToken();
        return $userToken === $storedToken; // Timing attack
    }

    private function getStoredToken(): string
    {
        return 'secret_token_value';
    }

    // =========================================================================
    // SSRF/RFI via Variables
    // =========================================================================

    public function ssrfViaVariable(): void
    {
        $url = $_GET['url'];
        $content = file_get_contents($url);
    }

    public function ssrfViaCurl(): void
    {
        $endpoint = $_POST['endpoint'];
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
    }

    public function ssrfViaGetHeaders(): void
    {
        $url = $_GET['check_url'];
        $headers = get_headers($url);
    }

    // =========================================================================
    // Header Injection via Variables
    // =========================================================================

    public function headerViaVariable(): void
    {
        $redirect = $_GET['return'];
        header("Location: " . $redirect);
    }

    public function headerViaCookieValue(): void
    {
        $preference = $_POST['theme'];
        setcookie('theme', $preference, time() + 3600);
    }

    // =========================================================================
    // Log Injection
    // =========================================================================

    public function logInjection(): void
    {
        $username = $_POST['username'];
        error_log("Login attempt for user: " . $username);
    }

    public function logInjectionViaFile(): void
    {
        $action = $_GET['action'];
        file_put_contents('/var/log/app.log', date('Y-m-d H:i:s') . " - " . $action . "\n", FILE_APPEND);
    }
}
