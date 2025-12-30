<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;
use PDO;

/**
 * SAFE: Using Aura.Sql methods with prepared statements
 *
 * Expected: No TaintedSql (values are safely bound via $values parameter)
 *
 * Aura.Sql's perform(), fetch*(), and yield*() methods support prepared
 * statements through the $values parameter, which safely binds user input.
 */
class AuraSqlPrepared extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    // =========================================================================
    // PdoInterface methods - safe usage
    // =========================================================================

    public function onGet(string $id): static
    {
        // SAFE: Using prepare() with bound parameters
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $this->body = $stmt->fetchAll();

        return $this;
    }

    public function onPost(string $name): static
    {
        // SAFE: Using quote() for escaping
        $quotedName = $this->pdo->quote($name);
        $this->body = $this->pdo->query("SELECT * FROM users WHERE name = {$quotedName}")->fetchAll();

        return $this;
    }

    // =========================================================================
    // ExtendedPdoInterface execute methods - safe usage
    // =========================================================================

    public function onPut(string $id): static
    {
        // SAFE: Using perform() with bound values
        $stmt = $this->pdo->perform(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
        $this->body = $stmt->fetchAll();

        return $this;
    }

    public function onPatch(string $id): static
    {
        // SAFE: Using prepareWithValues() with bound values
        $stmt = $this->pdo->prepareWithValues(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
        $this->body = $stmt->fetchAll();

        return $this;
    }

    public function onDelete(string $column): static
    {
        // SAFE: Using quoteName() for identifier escaping
        $quotedColumn = $this->pdo->quoteName($column);
        $this->body = $this->pdo->fetchAll("SELECT {$quotedColumn} FROM users");

        return $this;
    }

    public function onOptions(string $table): static
    {
        // SAFE: Using quoteSingleName() for table name escaping
        $quotedTable = $this->pdo->quoteSingleName($table);
        $this->body = $this->pdo->fetchAll("SELECT * FROM {$quotedTable}");

        return $this;
    }

    // =========================================================================
    // ExtendedPdoInterface fetch* methods - safe usage with $values
    // =========================================================================

    /**
     * Safe: fetchAffected with bound values
     */
    public function fetchAffectedSafe(string $id): int
    {
        return $this->pdo->fetchAffected(
            'DELETE FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchAll with bound values
     */
    public function fetchAllSafe(string $name): array
    {
        return $this->pdo->fetchAll(
            'SELECT * FROM users WHERE name = :name',
            ['name' => $name]
        );
    }

    /**
     * Safe: fetchAssoc with bound values
     */
    public function fetchAssocSafe(string $id): array
    {
        return $this->pdo->fetchAssoc(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchCol with bound values
     */
    public function fetchColSafe(string $id): array
    {
        return $this->pdo->fetchCol(
            'SELECT name FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchGroup with bound values
     */
    public function fetchGroupSafe(string $id): array
    {
        return $this->pdo->fetchGroup(
            'SELECT role, name FROM users WHERE id = :id',
            ['id' => $id],
            PDO::FETCH_COLUMN
        );
    }

    /**
     * Safe: fetchObject with bound values
     */
    public function fetchObjectSafe(string $id): object|false
    {
        return $this->pdo->fetchObject(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchObjects with bound values
     */
    public function fetchObjectsSafe(string $id): array
    {
        return $this->pdo->fetchObjects(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchOne with bound values
     */
    public function fetchOneSafe(string $id): array|false
    {
        return $this->pdo->fetchOne(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchPairs with bound values
     */
    public function fetchPairsSafe(string $id): array
    {
        return $this->pdo->fetchPairs(
            'SELECT id, name FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: fetchValue with bound values
     */
    public function fetchValueSafe(string $id): mixed
    {
        return $this->pdo->fetchValue(
            'SELECT name FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    // =========================================================================
    // ExtendedPdoInterface yield* methods - safe usage with $values
    // =========================================================================

    /**
     * Safe: yieldAll with bound values
     *
     * @return \Generator<array>
     */
    public function yieldAllSafe(string $id): \Generator
    {
        return $this->pdo->yieldAll(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: yieldAssoc with bound values
     *
     * @return \Generator<string, array>
     */
    public function yieldAssocSafe(string $id): \Generator
    {
        return $this->pdo->yieldAssoc(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: yieldCol with bound values
     *
     * @return \Generator<mixed>
     */
    public function yieldColSafe(string $id): \Generator
    {
        return $this->pdo->yieldCol(
            'SELECT name FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: yieldObjects with bound values
     *
     * @return \Generator<object>
     */
    public function yieldObjectsSafe(string $id): \Generator
    {
        return $this->pdo->yieldObjects(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    /**
     * Safe: yieldPairs with bound values
     *
     * @return \Generator<mixed, mixed>
     */
    public function yieldPairsSafe(string $id): \Generator
    {
        return $this->pdo->yieldPairs(
            'SELECT id, name FROM users WHERE id = :id',
            ['id' => $id]
        );
    }

    // =========================================================================
    // ExtendedPdoInterface quote methods - escape functions
    // =========================================================================

    /**
     * Safe: quoteName for identifier escaping
     */
    public function quoteNameSafe(string $column): array
    {
        $quotedColumn = $this->pdo->quoteName($column);

        return $this->pdo->fetchAll("SELECT {$quotedColumn} FROM users");
    }

    /**
     * Safe: quoteSingleName for single identifier escaping
     */
    public function quoteSingleNameSafe(string $table): array
    {
        $quotedTable = $this->pdo->quoteSingleName($table);

        return $this->pdo->fetchAll("SELECT * FROM {$quotedTable}");
    }
}
