<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use BEAR\Resource\ResourceObject;
use PDO;

/**
 * VULNERABLE: Direct SQL concatenation
 *
 * Expected: TaintedSql detection
 *
 * Note: In real BEAR.Sunday apps, user input comes via method parameters.
 * This demo uses $_GET directly to demonstrate taint flow.
 * When BEAR.Resource has taint annotations, method parameters will be tracked.
 */
class SqlInjection extends ResourceObject
{
    public function __construct(
        private PDO $pdo,
    ) {
    }

    public function onGet(): static
    {
        // Simulating user input from query parameter
        $id = $_GET['id'] ?? '';

        // VULNERABLE: SQL injection via string concatenation
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }
}
