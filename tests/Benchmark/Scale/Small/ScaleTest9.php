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
class ScaleTest9
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
        system("ping " . $_GET['host']);
    }

    /**
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        require($_POST['module']);
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize(base64_decode($_POST['obj']));
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
     * Vulnerable: xss injection
     */
    public function vulnerablexss1(): void
    {
        // Intentionally vulnerable for benchmarking
        echo $_GET['message'];
    }

    private function helper0(int $id): int
    {
        return $id * 2;
    }

    protected function validate3(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper1(int $id): int
    {
        return $id * 2;
    }

    protected function validate2(string $input): bool
    {
        return strlen($input) > 0;
    }
}
