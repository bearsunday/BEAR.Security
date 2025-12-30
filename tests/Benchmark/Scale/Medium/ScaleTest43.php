<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\Scale;

/**
 * Auto-generated scale test file
 * DO NOT use in production
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class ScaleTest43
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    private function helper2(int $id): int
    {
        return $id * 2;
    }

    private function helper3(int $id): int
    {
        return $id * 2;
    }

    public function safeMethod8(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    protected function validate9(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate5(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate7(string $input): bool
    {
        return strlen($input) > 0;
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        shell_exec("cat " . $_POST['file']);
    }

    public function safeMethod4(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    protected function validate6(string $input): bool
    {
        return strlen($input) > 0;
    }

    /**
     * Vulnerable: xss injection
     */
    public function vulnerablexss1(): void
    {
        // Intentionally vulnerable for benchmarking
        echo "<div>" . $_POST['content'] . "</div>";
    }

    public function safeMethod0(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    /**
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        include($_GET['page']);
    }

    /**
     * Vulnerable: sql injection
     */
    public function vulnerablesql0(): void
    {
        // Intentionally vulnerable for benchmarking
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize($_COOKIE['data']);
    }

    protected function validate1(string $input): bool
    {
        return strlen($input) > 0;
    }
}
