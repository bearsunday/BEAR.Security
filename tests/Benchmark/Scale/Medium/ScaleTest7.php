<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\Scale\Medium;

/**
 * Auto-generated scale test file
 * DO NOT use in production
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class ScaleTest7
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        exec("ls " . $_GET['path']);
    }

    private function helper1(int $id): int
    {
        return $id * 2;
    }

    private function helper5(int $id): int
    {
        return $id * 2;
    }

    private function helper3(int $id): int
    {
        return $id * 2;
    }

    protected function validate4(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod2(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    /**
     * Vulnerable: sql injection
     */
    public function vulnerablesql0(): void
    {
        // Intentionally vulnerable for benchmarking
        $this->pdo->query("SELECT * FROM orders WHERE user_id = " . $_POST['user']);
    }

    /**
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        include($_GET['page']);
    }

    protected function validate9(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper6(int $id): int
    {
        return $id * 2;
    }

    protected function validate8(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod7(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    public function safeMethod0(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    /**
     * Vulnerable: xss injection
     */
    public function vulnerablexss1(): void
    {
        // Intentionally vulnerable for benchmarking
        echo "<div>" . $_POST['content'] . "</div>";
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize($_COOKIE['data']);
    }
}
