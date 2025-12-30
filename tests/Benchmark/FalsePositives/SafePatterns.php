<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\FalsePositives;

/**
 * False Positive Test Cases
 *
 * These patterns look suspicious but are actually safe.
 * A good scanner should NOT flag these.
 * Used to measure precision (false positive rate).
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class SafePatterns
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    // =========================================================================
    // Safe SQL Patterns
    // =========================================================================

    /**
     * Safe: Prepared statement with positional parameters
     */
    public function sqlPreparedPositional(string $id): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetchAll();
    }

    /**
     * Safe: Prepared statement with named parameters
     */
    public function sqlPreparedNamed(string $name, string $email): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE name = :name AND email = :email");
        $stmt->execute(['name' => $name, 'email' => $email]);
        return $stmt->fetchAll();
    }

    /**
     * Safe: PDO with bindValue
     */
    public function sqlBindValue(int $id): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM orders WHERE user_id = :id");
        $stmt->bindValue(':id', $id, \PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Safe: Query with no user input (static)
     */
    public function sqlStaticQuery(): array
    {
        return $this->pdo->query("SELECT COUNT(*) FROM users WHERE active = 1")->fetchAll();
    }

    /**
     * Safe: PDO exec() is not shell exec()
     */
    public function sqlPdoExec(): int
    {
        return $this->pdo->exec("UPDATE stats SET count = count + 1");
    }

    /**
     * Safe: Whitelist-based table selection
     */
    public function sqlWhitelistTable(string $table): array
    {
        $allowed = ['users', 'orders', 'products'];
        if (!in_array($table, $allowed, true)) {
            throw new \InvalidArgumentException('Invalid table');
        }
        return $this->pdo->query("SELECT * FROM {$table}")->fetchAll();
    }

    /**
     * Safe: Integer cast for ID
     */
    public function sqlIntegerCast(string $id): array
    {
        $safeId = (int) $id;
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$safeId]);
        return $stmt->fetchAll();
    }

    // =========================================================================
    // Safe XSS Patterns
    // =========================================================================

    /**
     * Safe: htmlspecialchars with proper flags
     */
    public function xssHtmlspecialchars(string $input): void
    {
        echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Safe: htmlentities
     */
    public function xssHtmlentities(string $input): void
    {
        echo htmlentities($input, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Safe: strip_tags
     */
    public function xssStripTags(string $input): void
    {
        echo strip_tags($input);
    }

    /**
     * Safe: Output in JSON context with proper encoding
     */
    public function xssJsonEncode(array $data): void
    {
        header('Content-Type: application/json');
        echo json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }

    /**
     * Safe: Template engine auto-escaping (simulated)
     */
    public function xssTemplateEscape(string $name): string
    {
        // Twig/Blade/etc. auto-escape
        return sprintf('<div>%s</div>', $this->escape($name));
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Safe: Content-Security-Policy prevents inline execution
     */
    public function xssWithCsp(string $data): void
    {
        header("Content-Security-Policy: default-src 'self'");
        echo $data; // Still not recommended, but CSP mitigates
    }

    // =========================================================================
    // Safe Command Execution Patterns
    // =========================================================================

    /**
     * Safe: escapeshellarg
     */
    public function cmdEscapeshellarg(string $filename): string
    {
        $safe = escapeshellarg($filename);
        return (string) shell_exec("cat {$safe}");
    }

    /**
     * Safe: escapeshellcmd
     */
    public function cmdEscapeshellcmd(string $command): string
    {
        $safe = escapeshellcmd($command);
        return (string) shell_exec($safe);
    }

    /**
     * Safe: Whitelist-based command
     */
    public function cmdWhitelist(string $action): string
    {
        $commands = [
            'status' => 'git status',
            'log' => 'git log --oneline -10',
            'branch' => 'git branch',
        ];

        if (!isset($commands[$action])) {
            throw new \InvalidArgumentException('Invalid action');
        }

        return (string) shell_exec($commands[$action]);
    }

    /**
     * Safe: No user input in command
     */
    public function cmdStatic(): string
    {
        return (string) shell_exec('date +%Y-%m-%d');
    }

    /**
     * Safe: Symfony Process component (simulated)
     */
    public function cmdProcessComponent(string $filename): string
    {
        // Process component properly escapes arguments
        $process = new FakeProcess(['cat', $filename]);
        $process->run();
        return $process->getOutput();
    }

    // =========================================================================
    // Safe File Operations
    // =========================================================================

    /**
     * Safe: basename removes directory traversal
     */
    public function pathBasename(string $filename): string
    {
        $safe = basename($filename);
        return file_get_contents("/uploads/{$safe}") ?: '';
    }

    /**
     * Safe: realpath with base directory check
     */
    public function pathRealpath(string $filename): string
    {
        $basePath = '/var/www/uploads/';
        $realPath = realpath($basePath . $filename);

        if ($realPath === false || strpos($realPath, $basePath) !== 0) {
            throw new \InvalidArgumentException('Invalid path');
        }

        return file_get_contents($realPath) ?: '';
    }

    /**
     * Safe: Whitelist-based file inclusion
     */
    public function pathWhitelist(string $page): void
    {
        $allowed = ['home', 'about', 'contact'];
        if (!in_array($page, $allowed, true)) {
            throw new \InvalidArgumentException('Invalid page');
        }
        include "/templates/{$page}.php";
    }

    /**
     * Safe: Extension validation
     */
    public function pathExtensionCheck(string $filename): string
    {
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        $safe = basename($filename);

        if (!in_array($ext, ['txt', 'pdf', 'jpg'], true)) {
            throw new \InvalidArgumentException('Invalid file type');
        }

        return file_get_contents("/uploads/{$safe}") ?: '';
    }

    // =========================================================================
    // Safe Serialization
    // =========================================================================

    /**
     * Safe: unserialize with allowed_classes = false
     */
    public function deserializeNoClasses(string $data): mixed
    {
        return unserialize($data, ['allowed_classes' => false]);
    }

    /**
     * Safe: unserialize with specific allowed classes
     */
    public function deserializeWhitelist(string $data): mixed
    {
        return unserialize($data, ['allowed_classes' => [\stdClass::class, \DateTime::class]]);
    }

    /**
     * Safe: json_decode instead of unserialize
     */
    public function deserializeJson(string $data): mixed
    {
        return json_decode($data, true, 512, JSON_THROW_ON_ERROR);
    }

    // =========================================================================
    // Safe Cryptography
    // =========================================================================

    /**
     * Safe: md5 for non-security purposes (cache key)
     */
    public function hashCacheKey(string $content): string
    {
        return 'cache_' . md5($content);
    }

    /**
     * Safe: md5 for checksum (not password)
     */
    public function hashChecksum(string $file): string
    {
        return md5_file($file) ?: '';
    }

    /**
     * Safe: password_hash for passwords
     */
    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Safe: hash_equals for timing-safe comparison
     */
    public function compareTokens(string $provided, string $stored): bool
    {
        return hash_equals($stored, $provided);
    }

    /**
     * Safe: random_bytes for secure random
     */
    public function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    // =========================================================================
    // Safe Session Handling
    // =========================================================================

    /**
     * Safe: session_regenerate_id after login
     */
    public function loginWithRegenerate(int $userId): void
    {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
    }

    /**
     * Safe: Secure cookie settings
     */
    public function setSecureCookie(string $name, string $value): void
    {
        setcookie($name, $value, [
            'expires' => time() + 3600,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    // =========================================================================
    // Safe Redirect
    // =========================================================================

    /**
     * Safe: Whitelist-based redirect
     */
    public function redirectWhitelist(string $page): void
    {
        $allowed = ['/dashboard', '/profile', '/settings'];
        if (in_array($page, $allowed, true)) {
            header("Location: {$page}");
            exit;
        }
        header('Location: /');
    }

    /**
     * Safe: Same-host redirect validation
     */
    public function redirectSameHost(string $url): void
    {
        $parsed = parse_url($url);
        $currentHost = $_SERVER['HTTP_HOST'] ?? '';

        if (!isset($parsed['host']) || $parsed['host'] === $currentHost) {
            header("Location: {$url}");
            exit;
        }
        header('Location: /');
    }

    // =========================================================================
    // Safe XML Handling
    // =========================================================================

    /**
     * Safe: DOMDocument with network access disabled
     */
    public function xmlDomSafe(string $xml): \DOMDocument
    {
        $doc = new \DOMDocument();
        $doc->loadXML($xml, LIBXML_NONET);
        return $doc;
    }

    /**
     * Safe: SimpleXML without entity expansion
     */
    public function xmlSimpleSafe(string $xml): \SimpleXMLElement
    {
        // LIBXML_NONET prevents network access
        $result = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET);
        return $result ?: new \SimpleXMLElement('<empty/>');
    }

    // =========================================================================
    // Safe Assert Usage
    // =========================================================================

    /**
     * Safe: assert for type checking
     */
    public function assertInstanceOf(object $obj): void
    {
        assert($obj instanceof \stdClass);
    }

    /**
     * Safe: assert with literal boolean expression
     */
    public function assertCondition(int $value): void
    {
        assert($value > 0, 'Value must be positive');
    }

    // =========================================================================
    // Safe parse_str Usage
    // =========================================================================

    /**
     * Safe: parse_str with second parameter
     */
    public function parseStrSafe(string $query): array
    {
        parse_str($query, $result);
        return $result;
    }

    // =========================================================================
    // Placeholder Patterns (Not Real Secrets)
    // =========================================================================

    /**
     * Safe: Placeholder values, not real secrets
     */
    public function placeholderSecrets(): array
    {
        return [
            'api_key' => 'YOUR_API_KEY_HERE',
            'secret' => 'REPLACE_WITH_YOUR_SECRET',
            'password' => 'changeme',
            'token' => '<INSERT_TOKEN>',
            'aws_key' => 'AKIAEXAMPLEKEY12345',
        ];
    }

    /**
     * Safe: Environment variable usage
     */
    public function envSecrets(): array
    {
        return [
            'api_key' => getenv('API_KEY'),
            'db_password' => $_ENV['DB_PASSWORD'] ?? '',
        ];
    }
}

class FakeProcess
{
    private array $command;
    private string $output = '';

    public function __construct(array $command)
    {
        $this->command = $command;
    }

    public function run(): void
    {
        $this->output = 'fake output';
    }

    public function getOutput(): string
    {
        return $this->output;
    }
}
