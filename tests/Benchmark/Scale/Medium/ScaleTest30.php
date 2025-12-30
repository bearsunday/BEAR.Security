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
class ScaleTest30
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

    protected function validate0(string $input): bool
    {
        return strlen($input) > 0;
    }

    public function safeMethod3(): void
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

    protected function validate6(string $input): bool
    {
        return strlen($input) > 0;
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
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    }

    /**
     * Vulnerable: deserialize injection
     */
    public function vulnerabledeserialize4(): void
    {
        // Intentionally vulnerable for benchmarking
        unserialize(base64_decode($_POST['obj']));
    }

    protected function validate8(string $input): bool
    {
        return strlen($input) > 0;
    }

    /**
     * Vulnerable: cmd injection
     */
    public function vulnerablecmd2(): void
    {
        // Intentionally vulnerable for benchmarking
        exec("ls " . $_GET['path']);
    }

    public function safeMethod1(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    public function safeMethod5(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    public function safeMethod4(): void
    {
        $data = ['key' => 'value'];
        $result = array_map(fn($x) => $x * 2, [1, 2, 3]);
    }

    protected function validate9(string $input): bool
    {
        return strlen($input) > 0;
    }

    protected function validate7(string $input): bool
    {
        return strlen($input) > 0;
    }
}
