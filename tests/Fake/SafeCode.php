<?php

declare(strict_types=1);

namespace BEAR\Security\Fake;

/**
 * This file contains safe code patterns that should NOT trigger the security scanner.
 *
 * Used to test false positive reduction. All patterns here are intentionally
 * safe and should pass without warnings.
 *
 * @psalm-suppress all
 */
class SafeCode
{
    // =========================================================================
    // Safe SQL Patterns
    // =========================================================================

    /**
     * Safe SQL with prepared statements (positional)
     *
     * @return array<mixed>
     */
    public function safeSql(\PDO $pdo, string $id): array
    {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetchAll();
    }

    /**
     * Safe SQL with named parameters
     *
     * @return array<mixed>
     */
    public function safeSqlNamed(\PDO $pdo, string $name, string $email): array
    {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name AND email = :email");
        $stmt->execute(['name' => $name, 'email' => $email]);
        return $stmt->fetchAll();
    }

    /**
     * Safe SQL with bindValue
     *
     * @return array<mixed>
     */
    public function safeSqlBindValue(\PDO $pdo, int $id): array
    {
        $stmt = $pdo->prepare("SELECT * FROM orders WHERE user_id = :id");
        $stmt->bindValue(':id', $id, \PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Safe: PDO::exec() is NOT shell exec()
     */
    public function safePdoExec(\PDO $pdo): int
    {
        return $pdo->exec("UPDATE stats SET count = count + 1");
    }

    /**
     * Safe: Static query with no user input
     *
     * @return array<mixed>
     */
    public function safeSqlStatic(\PDO $pdo): array
    {
        return $pdo->query("SELECT COUNT(*) FROM users WHERE active = 1")->fetchAll();
    }

    /**
     * Safe: Whitelist-based table selection
     *
     * @return array<mixed>
     */
    public function safeSqlWhitelist(\PDO $pdo, string $table): array
    {
        $allowed = ['users', 'orders', 'products'];
        if (!in_array($table, $allowed, true)) {
            throw new \InvalidArgumentException('Invalid table');
        }
        return $pdo->query("SELECT * FROM {$table}")->fetchAll();
    }

    // =========================================================================
    // Safe Non-SQL Query Patterns (Should NOT match SQL injection)
    // =========================================================================

    /**
     * Safe: Cache query is NOT SQL
     */
    public function safeCacheQuery(object $cache, string $key): mixed
    {
        // $cache->query() should not be flagged as SQL injection
        return $cache->query($key);
    }

    /**
     * Safe: Redis exec is NOT shell exec
     */
    public function safeRedisExec(object $redis): array
    {
        // $redis->exec() in pipeline/transaction is not shell exec
        $redis->multi();
        $redis->set('key', 'value');
        return $redis->exec();
    }

    /**
     * Safe: Elasticsearch query is NOT SQL
     */
    public function safeElasticsearchQuery(object $client, array $params): array
    {
        return $client->query($params);
    }

    /**
     * Safe: Query builder is NOT raw SQL
     */
    public function safeQueryBuilder(object $builder, string $field): object
    {
        return $builder->query()->where($field, '=', 'value');
    }

    // =========================================================================
    // Safe XSS Patterns
    // =========================================================================

    /**
     * Safe output with escaping
     */
    public function safeOutput(string $message): void
    {
        echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Safe output with htmlentities
     */
    public function safeOutputEntities(string $input): void
    {
        echo htmlentities($input, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Safe: strip_tags
     */
    public function safeStripTags(string $input): void
    {
        echo strip_tags($input);
    }

    /**
     * Safe: JSON output with proper encoding
     */
    public function safeJsonOutput(array $data): void
    {
        header('Content-Type: application/json');
        echo json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }

    // =========================================================================
    // Safe Command Execution Patterns
    // =========================================================================

    /**
     * Safe command execution with escaping
     */
    public function safeCommand(string $filename): string
    {
        $safeFilename = escapeshellarg($filename);

        return (string) shell_exec("cat $safeFilename");
    }

    /**
     * Safe: escapeshellcmd
     */
    public function safeCommandCmd(string $command): string
    {
        $safe = escapeshellcmd($command);
        return (string) shell_exec($safe);
    }

    /**
     * Safe: Whitelist-based command
     */
    public function safeCommandWhitelist(string $action): string
    {
        $commands = [
            'status' => 'git status',
            'log' => 'git log --oneline -10',
        ];
        if (!isset($commands[$action])) {
            throw new \InvalidArgumentException('Invalid action');
        }
        return (string) shell_exec($commands[$action]);
    }

    /**
     * Safe: Static command with no user input
     */
    public function safeCommandStatic(): string
    {
        return (string) shell_exec('date +%Y-%m-%d');
    }

    // =========================================================================
    // Safe File Operations
    // =========================================================================

    /**
     * Safe file operations with validation
     */
    public function safeFileRead(string $filename): string
    {
        $basePath = '/var/www/files/';
        $realPath = realpath($basePath . basename($filename));

        if ($realPath === false || strpos($realPath, $basePath) !== 0) {
            throw new \InvalidArgumentException('Invalid file path');
        }

        return file_get_contents($realPath) ?: '';
    }

    /**
     * Safe: basename removes directory traversal
     */
    public function safeBasename(string $filename): string
    {
        $safe = basename($filename);
        return file_get_contents("/uploads/{$safe}") ?: '';
    }

    /**
     * Safe: Whitelist-based file inclusion
     */
    public function safeIncludeWhitelist(string $page): void
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
    public function safeExtensionCheck(string $filename): string
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
     * Safe unserialize with allowed_classes
     */
    public function safeUnserialize(string $data): mixed
    {
        return unserialize($data, ['allowed_classes' => false]);
    }

    /**
     * Safe: unserialize with specific allowed classes
     */
    public function safeUnserializeWhitelist(string $data): mixed
    {
        return unserialize($data, ['allowed_classes' => [\stdClass::class, \DateTime::class]]);
    }

    /**
     * Safe: json_decode instead of unserialize
     */
    public function safeJsonDecode(string $data): mixed
    {
        return json_decode($data, true, 512, JSON_THROW_ON_ERROR);
    }

    // =========================================================================
    // Safe Cryptography
    // =========================================================================

    /**
     * Safe: md5 for cache key (not password)
     */
    public function safeMd5CacheKey(string $content): string
    {
        return 'cache_' . md5($content);
    }

    /**
     * Safe: md5 for checksum
     */
    public function safeMd5Checksum(string $file): string
    {
        return md5_file($file) ?: '';
    }

    /**
     * Safe: password_hash for passwords
     */
    public function safePasswordHash(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Safe: hash_equals for timing-safe comparison
     */
    public function safeHashEquals(string $provided, string $stored): bool
    {
        return hash_equals($stored, $provided);
    }

    /**
     * Safe: random_bytes for secure random
     */
    public function safeRandomBytes(): string
    {
        return bin2hex(random_bytes(32));
    }

    // =========================================================================
    // Safe Session Handling
    // =========================================================================

    /**
     * Safe: session_regenerate_id after login
     */
    public function safeSessionRegenerate(int $userId): void
    {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
    }

    /**
     * Safe: Secure cookie settings
     */
    public function safeSecureCookie(string $name, string $value): void
    {
        setcookie($name, $value, [
            'expires' => time() + 3600,
            'path' => '/',
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
    public function safeRedirectWhitelist(string $page): void
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
    public function safeRedirectSameHost(string $url): void
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
     * Safe: DOMDocument with LIBXML_NONET
     */
    public function safeXmlDom(string $xml): \DOMDocument
    {
        $doc = new \DOMDocument();
        $doc->loadXML($xml, LIBXML_NONET);
        return $doc;
    }

    /**
     * Safe: SimpleXML with LIBXML_NONET
     */
    public function safeXmlSimple(string $xml): \SimpleXMLElement
    {
        $result = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET);
        return $result ?: new \SimpleXMLElement('<empty/>');
    }

    // =========================================================================
    // Safe Assert and Parse
    // =========================================================================

    /**
     * Safe assert with instanceof (type assertion)
     */
    public function safeAssert(object $obj): void
    {
        assert($obj instanceof \stdClass);
    }

    /**
     * Safe: assert with boolean expression
     */
    public function safeAssertCondition(int $value): void
    {
        assert($value > 0, 'Value must be positive');
    }

    /**
     * Safe parse_str with second parameter
     *
     * @return array<int|string, mixed>
     */
    public function safeParseStr(string $queryString): array
    {
        parse_str($queryString, $result);
        return $result;
    }

    // =========================================================================
    // Placeholder Patterns (Not Real Secrets)
    // =========================================================================

    /**
     * Safe: Placeholder values, not real secrets
     */
    public function safePlaceholders(): array
    {
        return [
            'api_key' => 'YOUR_API_KEY_HERE',
            'secret' => 'REPLACE_WITH_YOUR_SECRET',
            'password' => 'changeme',
            'token' => '<INSERT_TOKEN>',
        ];
    }

    /**
     * Safe: Environment variable usage
     */
    public function safeEnvSecrets(): array
    {
        return [
            'api_key' => getenv('API_KEY'),
            'db_password' => $_ENV['DB_PASSWORD'] ?? '',
        ];
    }
}
