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
class ScaleTest4
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    protected function validate6(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper0(int $id): int
    {
        return $id * 2;
    }

    /**
     * Vulnerable: sql injection
     */
    public function vulnerablesql0(): void
    {
        // Intentionally vulnerable for benchmarking
        $this->pdo->query("SELECT * FROM orders WHERE user_id = " . $_POST['user']);
    }

    private function helper9(int $id): int
    {
        return $id * 2;
    }

    private function helper2(int $id): int
    {
        return $id * 2;
    }

    private function helper8(int $id): int
    {
        return $id * 2;
    }

    /**
     * Vulnerable: xss injection
     */
    public function vulnerablexss1(): void
    {
        // Intentionally vulnerable for benchmarking
        echo $_GET['message'];
    }

    private function helper3(int $id): int
    {
        return $id * 2;
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        system("ping " . $_GET['host']);
    }

    public function safeMethod5(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    protected function validate4(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate7(string $input): bool
    {
        return strlen($input) > 0;
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize($_COOKIE['data']);
    }

    /**
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        include($_GET['page']);
    }

    protected function validate1(string $input): bool
    {
        return strlen($input) > 0;
    }
}
