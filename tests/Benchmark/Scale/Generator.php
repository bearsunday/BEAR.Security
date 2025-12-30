<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\Scale;

/**
 * Scale Test File Generator
 *
 * Generates PHP files with varying numbers of vulnerabilities
 * for performance benchmarking.
 *
 * Usage:
 *   php Generator.php small   # 10 files, ~50 vulnerabilities
 *   php Generator.php medium  # 50 files, ~250 vulnerabilities
 *   php Generator.php large   # 200 files, ~1000 vulnerabilities
 */
class Generator
{
    private const VULNERABILITY_TEMPLATES = [
        'sql' => [
            '$query = "SELECT * FROM users WHERE id = " . $_GET[\'id\'];',
            '$this->pdo->query("SELECT * FROM orders WHERE user_id = " . $_POST[\'user\']);',
            '$sql = "DELETE FROM items WHERE id = " . $_REQUEST[\'id\'];',
        ],
        'xss' => [
            'echo $_GET[\'message\'];',
            'echo "<div>" . $_POST[\'content\'] . "</div>";',
            'print($_REQUEST[\'output\']);',
        ],
        'cmd' => [
            'exec("ls " . $_GET[\'path\']);',
            'shell_exec("cat " . $_POST[\'file\']);',
            'system("ping " . $_GET[\'host\']);',
        ],
        'path' => [
            'include($_GET[\'page\']);',
            'require($_POST[\'module\']);',
            'file_get_contents($_GET[\'file\']);',
        ],
        'deserialize' => [
            'unserialize($_COOKIE[\'data\']);',
            'unserialize(base64_decode($_POST[\'obj\']));',
        ],
    ];

    private const SAFE_CODE_TEMPLATES = [
        'function getSafeData(): array { return [\'status\' => \'ok\']; }',
        'private string $name = \'\';',
        'public function process(int $id): void { $this->id = $id; }',
        'const VERSION = \'1.0.0\';',
        'protected array $items = [];',
        '/** @var int */ private int $count = 0;',
        'public function __construct(private readonly string $value) {}',
    ];

    public function generate(string $size): void
    {
        $config = match($size) {
            'small' => ['files' => 10, 'vulns_per_file' => 5, 'safe_lines' => 20],
            'medium' => ['files' => 50, 'vulns_per_file' => 5, 'safe_lines' => 50],
            'large' => ['files' => 200, 'vulns_per_file' => 5, 'safe_lines' => 100],
            default => throw new \InvalidArgumentException("Unknown size: $size"),
        };

        $dir = __DIR__ . '/' . ucfirst($size);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $totalVulns = 0;
        $subNamespace = ucfirst($size);
        for ($i = 1; $i <= $config['files']; $i++) {
            $vulns = $this->generateFile($dir, $i, $config, $subNamespace);
            $totalVulns += $vulns;
        }

        echo "Generated {$config['files']} files with $totalVulns vulnerabilities in $dir\n";
    }

    private function generateFile(string $dir, int $index, array $config, string $subNamespace): int
    {
        $className = "ScaleTest{$index}";
        $filename = "{$dir}/{$className}.php";

        $methods = [];
        $vulnCount = 0;

        // Add safe methods
        for ($i = 0; $i < $config['safe_lines'] / 5; $i++) {
            $methods[] = $this->generateSafeMethod($i);
        }

        // Add vulnerable methods
        foreach (self::VULNERABILITY_TEMPLATES as $type => $templates) {
            $template = $templates[array_rand($templates)];
            $methods[] = $this->generateVulnerableMethod($type, $vulnCount, $template);
            $vulnCount++;

            if ($vulnCount >= $config['vulns_per_file']) {
                break;
            }
        }

        shuffle($methods);

        $content = $this->buildClassFile($className, $methods, $subNamespace);
        file_put_contents($filename, $content);

        return $vulnCount;
    }

    private function generateSafeMethod(int $index): string
    {
        $templates = [
            "    public function safeMethod{$index}(): void\n    {\n        \$data = ['key' => 'value'];\n        \$result = array_map(fn(\$x) => \$x * 2, [1, 2, 3]);\n    }",
            "    private function helper{$index}(int \$id): int\n    {\n        return \$id * 2;\n    }",
            "    protected function validate{$index}(string \$input): bool\n    {\n        return strlen(\$input) > 0;\n    }",
        ];

        return $templates[array_rand($templates)];
    }

    private function generateVulnerableMethod(string $type, int $index, string $vuln): string
    {
        return <<<PHP
    /**
     * Vulnerable: $type injection
     */
    public function vulnerable{$type}{$index}(): void
    {
        // Intentionally vulnerable for benchmarking
        $vuln
    }
PHP;
    }

    private function buildClassFile(string $className, array $methods, string $subNamespace): string
    {
        $methodsStr = implode("\n\n", $methods);

        return <<<PHP
<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\Scale\\{$subNamespace};

/**
 * Auto-generated scale test file
 * DO NOT use in production
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class {$className}
{
    private \PDO \$pdo;

    public function __construct()
    {
        \$this->pdo = new \PDO('sqlite::memory:');
    }

{$methodsStr}
}

PHP;
    }
}

// CLI execution
if (PHP_SAPI === 'cli' && isset($argv[1])) {
    $generator = new Generator();
    $generator->generate($argv[1]);
}
