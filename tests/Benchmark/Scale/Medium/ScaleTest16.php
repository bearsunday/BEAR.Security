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
class ScaleTest16
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    private function helper0(int $id): int
    {
        return $id * 2;
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
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize(base64_decode($_POST['obj']));
    }

    private function helper9(int $id): int
    {
        return $id * 2;
    }

    protected function validate8(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod6(): void
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
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
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
        echo $_GET['message'];
    }

    protected function validate4(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate3(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate1(string $input): bool
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

    protected function validate2(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper7(int $id): int
    {
        return $id * 2;
    }
}
