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
 * The plugin marks onGet($id) parameter as tainted.
 */
class SqlInjection extends ResourceObject
{
    public function __construct(
        private PDO $pdo,
    ) {
    }

    public function onGet(string $id): static
    {
        // VULNERABLE: SQL injection via string concatenation
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }
}
