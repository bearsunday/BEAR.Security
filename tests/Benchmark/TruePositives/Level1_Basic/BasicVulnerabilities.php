<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\TruePositives\Level1_Basic;

/**
 * Level 1: Basic Vulnerabilities
 *
 * Direct, obvious patterns that any scanner should detect.
 * Detection difficulty: Easy
 * Expected detection rate: 100%
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class BasicVulnerabilities
{
    // =========================================================================
    // SQL Injection (A03) - 5 patterns
    // =========================================================================

    public function sqlDirectConcat(): void
    {
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    }

    public function sqlQueryMethod(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM users WHERE name = '" . $_POST['name'] . "'");
    }

    public function sqlExecMethod(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->exec("DELETE FROM users WHERE id = " . $_REQUEST['id']);
    }

    public function sqlMysqliQuery(): void
    {
        $mysqli = new \mysqli('localhost', 'user', 'pass', 'db');
        $mysqli->query("SELECT * FROM orders WHERE user_id = " . $_GET['user']);
    }

    public function sqlInterpolation(): void
    {
        $id = $_GET['id'];
        $query = "UPDATE users SET active = 1 WHERE id = $id";
    }

    // =========================================================================
    // XSS (A03) - 5 patterns
    // =========================================================================

    public function xssDirectEcho(): void
    {
        echo $_GET['message'];
    }

    public function xssPrint(): void
    {
        print($_POST['content']);
    }

    public function xssInHtml(): void
    {
        echo "<div class='user'>" . $_GET['name'] . "</div>";
    }

    public function xssInAttribute(): void
    {
        echo "<input value='" . $_POST['value'] . "'>";
    }

    public function xssPrintf(): void
    {
        printf("<span>%s</span>", $_GET['text']);
    }

    // =========================================================================
    // Command Injection (A03) - 5 patterns
    // =========================================================================

    public function cmdExec(): void
    {
        exec("ls " . $_GET['path']);
    }

    public function cmdShellExec(): void
    {
        shell_exec("cat " . $_POST['file']);
    }

    public function cmdSystem(): void
    {
        system("ping " . $_GET['host']);
    }

    public function cmdPassthru(): void
    {
        passthru("grep " . $_POST['pattern'] . " /var/log/app.log");
    }

    public function cmdBacktick(): void
    {
        $output = `whoami && ${_GET['cmd']}`;
    }

    // =========================================================================
    // Path Traversal (A01) - 4 patterns
    // =========================================================================

    public function pathInclude(): void
    {
        include($_GET['page']);
    }

    public function pathRequire(): void
    {
        require($_POST['module']);
    }

    public function pathFileGetContents(): void
    {
        $content = file_get_contents($_GET['file']);
    }

    public function pathFopen(): void
    {
        $handle = fopen($_POST['path'], 'r');
    }

    // =========================================================================
    // Dangerous Functions (A03) - 4 patterns
    // =========================================================================

    public function dangerousEval(): void
    {
        eval($_POST['code']);
    }

    public function dangerousAssert(): void
    {
        assert($_GET['expr']);
    }

    public function dangerousCreateFunction(): void
    {
        $func = create_function('$x', $_POST['body']);
    }

    public function dangerousPreg(): void
    {
        preg_replace('/.*/e', $_GET['replace'], 'subject');
    }

    // =========================================================================
    // Insecure Deserialization (A08) - 2 patterns
    // =========================================================================

    public function deserializeNoOptions(): void
    {
        $data = unserialize($_COOKIE['data']);
    }

    public function deserializeAllClasses(): void
    {
        $obj = unserialize($_POST['object'], ['allowed_classes' => true]);
    }

    // =========================================================================
    // Session Security (A07) - 3 patterns
    // =========================================================================

    public function sessionFixation(): void
    {
        session_id($_GET['sid']);
    }

    public function sessionNoRegenerate(): void
    {
        $_SESSION['user_id'] = $_POST['user_id'];
        // Missing session_regenerate_id()
    }

    public function sessionInsecureCookie(): void
    {
        setcookie('session', $_GET['token'], 0, '/', '', false, false);
    }

    // =========================================================================
    // Open Redirect (A01) - 2 patterns
    // =========================================================================

    public function redirectHeader(): void
    {
        header("Location: " . $_GET['url']);
    }

    public function redirectHeaderRaw(): void
    {
        header_remove();
        header("Location: " . $_POST['redirect']);
    }

    // =========================================================================
    // Cryptographic Failures (A02) - 3 patterns
    // =========================================================================

    public function weakHashMd5(): void
    {
        $hash = md5($_POST['password']);
    }

    public function weakHashSha1(): void
    {
        $hash = sha1($_POST['password']);
    }

    public function hardcodedSecret(): void
    {
        $apiKey = "sk_live_abc123def456ghi789";
        $awsKey = "AKIAIOSFODNN7EXAMPLE";
    }

    // =========================================================================
    // XXE (A05) - 2 patterns
    // =========================================================================

    public function xxeSimpleXml(): void
    {
        $xml = simplexml_load_string($_POST['xml']);
    }

    public function xxeDomDocument(): void
    {
        $doc = new \DOMDocument();
        $doc->loadXML($_POST['xml']);
    }

    // =========================================================================
    // Header Injection (A05) - 2 patterns
    // =========================================================================

    public function headerInjection(): void
    {
        header("X-Custom: " . $_GET['value']);
    }

    public function headerSetCookie(): void
    {
        header("Set-Cookie: user=" . $_POST['user']);
    }

    // =========================================================================
    // Weak Random (A02) - 2 patterns
    // =========================================================================

    public function weakRandToken(): void
    {
        $token = md5(rand());
    }

    public function weakMtRand(): void
    {
        $code = mt_rand(100000, 999999);
    }
}
