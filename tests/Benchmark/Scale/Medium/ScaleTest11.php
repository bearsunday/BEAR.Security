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
class ScaleTest11
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    public function safeMethod7(): void
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

    private function helper0(int $id): int
    {
        return $id * 2;
    }

    protected function validate9(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate5(string $input): bool
    {
        return strlen($input) > 0;
    }

    private function helper1(int $id): int
    {
        return $id * 2;
    }

    public function safeMethod2(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    private function helper4(int $id): int
    {
        return $id * 2;
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
        unserialize($_COOKIE['data']);
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        shell_exec("cat " . $_POST['file']);
    }

    public function safeMethod3(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    public function safeMethod8(): void
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

    public function safeMethod6(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }
}
