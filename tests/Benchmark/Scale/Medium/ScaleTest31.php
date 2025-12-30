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
class ScaleTest31
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    protected function validate2(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper7(int $id): int
    {
        return $id * 2;
    }

    public function safeMethod5(): void
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
        echo $_GET['message'];
    }

    /**
     * Vulnerable: sql injection
     */
    public function vulnerablesql0(): void
    {
        // Intentionally vulnerable for benchmarking
        $pdo->query("SELECT * FROM orders WHERE user_id = " . $_POST['user']);
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize(base64_decode($_POST['obj']));
    }

    private function helper1(int $id): int
    {
        return $id * 2;
    }

    public function safeMethod3(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    protected function validate6(string $input): bool
    {
        return strlen($input) > 0;
    }

    /**
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        file_get_contents($_GET['file']);
    }

    protected function validate9(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod4(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    private function helper8(int $id): int
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

    private function helper0(int $id): int
    {
        return $id * 2;
    }
}
