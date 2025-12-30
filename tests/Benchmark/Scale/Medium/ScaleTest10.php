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
class ScaleTest10
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
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

    private function helper1(int $id): int
    {
        return $id * 2;
    }

    private function helper4(int $id): int
    {
        return $id * 2;
    }

    public function safeMethod6(): void
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
     * Vulnerable: sql injection
     */
    public function vulnerablesql0(): void
    {
        // Intentionally vulnerable for benchmarking
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    }

    private function helper3(int $id): int
    {
        return $id * 2;
    }

    private function helper5(int $id): int
    {
        return $id * 2;
    }

    protected function validate9(string $input): bool
    {
        return strlen($input) > 0;
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        system("ping " . $_GET['host']);
    }

    private function helper2(int $id): int
    {
        return $id * 2;
    }

    private function helper0(int $id): int
    {
        return $id * 2;
    }

    private function helper7(int $id): int
    {
        return $id * 2;
    }
}
