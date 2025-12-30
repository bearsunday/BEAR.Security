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
class ScaleTest4
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    protected function validate3(string $input): bool
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

    protected function validate5(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod9(): void
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
        $sql = "DELETE FROM items WHERE id = " . $_REQUEST['id'];
    }

    /**
     * Vulnerable: xss injection
     */
    public function vulnerablexss1(): void
    {
        // Intentionally vulnerable for benchmarking
        print($_REQUEST['output']);
    }

    protected function validate7(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper6(int $id): int
    {
        return $id * 2;
    }

    /**
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        file_get_contents($_GET['file']);
    }

    protected function validate8(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate4(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper2(int $id): int
    {
        return $id * 2;
    }

    protected function validate0(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper1(int $id): int
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
}
