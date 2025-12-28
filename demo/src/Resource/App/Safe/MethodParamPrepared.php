<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;

/**
 * SAFE: Method parameters with prepared statements
 *
 * Tests that taint is escaped when using prepared statements.
 * Expected: No TaintedSql errors.
 */
class MethodParamPrepared extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    public function onGet(string $id): static
    {
        // SAFE: Using perform() with bound values
        $stmt = $this->pdo->perform(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
        $this->body = $stmt->fetchAll();

        return $this;
    }

    public function onPost(string $name, string $email): static
    {
        // SAFE: Using perform() with multiple bound values
        $this->pdo->perform(
            'INSERT INTO users (name, email) VALUES (:name, :email)',
            ['name' => $name, 'email' => $email]
        );

        return $this;
    }

    public function onDelete(string $id): static
    {
        // SAFE: Using perform() for DELETE
        $this->pdo->perform(
            'DELETE FROM users WHERE id = :id',
            ['id' => $id]
        );

        return $this;
    }
}
