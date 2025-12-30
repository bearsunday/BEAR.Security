<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;

/**
 * SAFE: Edge cases that should NOT trigger TaintedSql
 *
 * These patterns test complex scenarios where taint analysis
 * must correctly track data flow and escape functions.
 */
class AuraSqlEdgeCases extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    /**
     * Safe: Variable reassignment with escaping
     *
     * User input is assigned to variable, then escaped before use.
     */
    public function onGet(string $userInput): static
    {
        $input = $userInput;
        $escaped = $this->pdo->quote($input);
        $this->body = $this->pdo->fetchAll("SELECT * FROM users WHERE name = {$escaped}");

        return $this;
    }

    /**
     * Safe: Chained escaping and use
     *
     * Direct chaining of quote() result into SQL.
     */
    public function onPost(string $name): static
    {
        $this->body = $this->pdo->fetchAll(
            "SELECT * FROM users WHERE name = " . $this->pdo->quote($name)
        );

        return $this;
    }

    /**
     * Safe: Multiple escaped values in single query
     */
    public function onPut(string $name, string $email): static
    {
        $this->body = $this->pdo->fetchAll(
            'SELECT * FROM users WHERE name = :name AND email = :email',
            ['name' => $name, 'email' => $email]
        );

        return $this;
    }

    /**
     * Safe: Mixed literal and bound values
     */
    public function onPatch(string $id): static
    {
        $this->body = $this->pdo->fetchAll(
            "SELECT * FROM users WHERE status = 'active' AND id = :id",
            ['id' => $id]
        );

        return $this;
    }

    /**
     * Safe: quoteName with dynamic column selection
     */
    public function onDelete(string $column, string $value): static
    {
        $quotedColumn = $this->pdo->quoteName($column);
        $this->body = $this->pdo->fetchAll(
            "SELECT {$quotedColumn} FROM users WHERE id = :id",
            ['id' => $value]
        );

        return $this;
    }

    /**
     * Safe: Combined quote methods
     */
    public function onOptions(string $table, string $column): static
    {
        $quotedTable = $this->pdo->quoteSingleName($table);
        $quotedColumn = $this->pdo->quoteName($column);
        $this->body = $this->pdo->fetchAll("SELECT {$quotedColumn} FROM {$quotedTable}");

        return $this;
    }
}
