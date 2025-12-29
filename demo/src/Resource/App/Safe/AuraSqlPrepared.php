<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;

/**
 * SAFE: Using Aura.Sql perform()/fetchAll() with prepared statements
 *
 * Expected: No TaintedSql (values are safely bound)
 *
 * Aura.Sql's perform() and fetch*() methods use prepared statements,
 * which safely bind user input.
 */
class AuraSqlPrepared extends ResourceObject
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

    public function onPost(string $name): static
    {
        // SAFE: Using fetchAll() with bound values
        $this->body = $this->pdo->fetchAll(
            'SELECT * FROM users WHERE name = :name',
            ['name' => $name]
        );

        return $this;
    }

    public function onPut(string $id, string $name): static
    {
        // SAFE: Using quote() for values
        $quotedName = $this->pdo->quote($name);
        $sql = "SELECT * FROM users WHERE name = {$quotedName} AND id = :id";
        $this->body = $this->pdo->fetchAll($sql, ['id' => $id]);

        return $this;
    }
}
