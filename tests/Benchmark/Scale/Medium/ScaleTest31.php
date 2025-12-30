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
class ScaleTest31
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize($_COOKIE['data']);
    }

    private function helper6(int $id): int
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

    protected function validate0(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper7(int $id): int
    {
        return $id * 2;
    }

    private function helper5(int $id): int
    {
        return $id * 2;
    }

    /**
     * Vulnerable: xss injection
     */
    public function vulnerablexss1(): void
    {
        // Intentionally vulnerable for benchmarking
        print($_REQUEST['output']);
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        shell_exec("cat " . $_POST['file']);
    }

    protected function validate4(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate1(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod8(): void
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
        require($_POST['module']);
    }

    private function helper3(int $id): int
    {
        return $id * 2;
    }

    public function safeMethod2(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    public function safeMethod9(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }
}
