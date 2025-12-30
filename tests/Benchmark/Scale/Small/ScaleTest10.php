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
class ScaleTest10
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    public function safeMethod2(): void
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
     * Vulnerable: sql injection
     */
    public function vulnerablesql0(): void
    {
        // Intentionally vulnerable for benchmarking
        $sql = "DELETE FROM items WHERE id = " . $_REQUEST['id'];
    }

    private function helper3(int $id): int
    {
        return $id * 2;
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize(base64_decode($_POST['obj']));
    }

    public function safeMethod1(): void
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
     * Vulnerable: path injection
     */
    public function vulnerablepath3(): void
    {
        // Intentionally vulnerable for benchmarking
        require($_POST['module']);
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
