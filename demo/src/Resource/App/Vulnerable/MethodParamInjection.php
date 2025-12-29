<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;

/**
 * VULNERABLE: SQL injection via method parameters
 *
 * Tests that taint flows through on* method parameters.
 * Expected: TaintedSql for each vulnerable method.
 */
class MethodParamInjection extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    public function onGet(string $id): static
    {
        // VULNERABLE: Direct concatenation with method parameter
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }

    public function onPost(string $name, string $email): static
    {
        // VULNERABLE: Multiple parameters in SQL
        $sql = "INSERT INTO users (name, email) VALUES ('" . $name . "', '" . $email . "')";
        $this->pdo->exec($sql);

        return $this;
    }

    public function onDelete(string $id): static
    {
        // VULNERABLE: DELETE with parameter
        $sql = "DELETE FROM users WHERE id = '" . $id . "'";
        $this->pdo->exec($sql);

        return $this;
    }
}
