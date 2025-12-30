<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;
use PDO;

/**
 * VULNERABLE: Using Aura.Sql methods with string concatenation
 *
 * All methods that accept SQL statements are vulnerable when
 * user input is concatenated directly into the query string.
 *
 * Expected: TaintedSql detection for all vulnerable patterns
 */
class AuraSqlInjection extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    // =========================================================================
    // PdoInterface methods (inherited)
    // =========================================================================

    public function onGet(string $id): static
    {
        // VULNERABLE: SQL injection via query()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }

    public function onPost(string $name): static
    {
        // VULNERABLE: SQL injection via exec()
        $sql = "DELETE FROM users WHERE name = '" . $name . "'";
        $this->pdo->exec($sql);

        return $this;
    }

    public function onPut(string $table): static
    {
        // VULNERABLE: SQL injection via prepare() with concatenation
        $sql = "SELECT * FROM " . $table . " WHERE id = :id";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(['id' => 1]);
        $this->body = $stmt->fetchAll();

        return $this;
    }

    // =========================================================================
    // ExtendedPdoInterface fetch* methods
    // =========================================================================

    public function onPatch(string $id): static
    {
        // VULNERABLE: SQL injection via fetchAll()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->fetchAll($sql);

        return $this;
    }

    public function onDelete(string $id): static
    {
        // VULNERABLE: SQL injection via multiple fetch methods
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        // Test various fetch methods
        $this->pdo->fetchAffected($sql);
        $this->pdo->fetchAssoc($sql);
        $this->pdo->fetchCol($sql);
        $this->pdo->fetchOne($sql);
        $this->pdo->fetchPairs($sql);
        $this->pdo->fetchValue($sql);
        $this->pdo->perform($sql);
        $this->pdo->prepareWithValues($sql, []);

        return $this;
    }

    public function onOptions(string $id): static
    {
        // VULNERABLE: SQL injection via yield methods
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        // Test yield methods (generators)
        $this->pdo->yieldAll($sql);
        $this->pdo->yieldAssoc($sql);
        $this->pdo->yieldCol($sql);
        $this->pdo->yieldPairs($sql);

        return $this;
    }

    /**
     * Test fetchAffected with concatenation
     */
    public function fetchAffectedVulnerable(string $id): int
    {
        // VULNERABLE: SQL injection via fetchAffected()
        $sql = "DELETE FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchAffected($sql);
    }

    /**
     * Test fetchAssoc with concatenation
     */
    public function fetchAssocVulnerable(string $id): array
    {
        // VULNERABLE: SQL injection via fetchAssoc()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchAssoc($sql);
    }

    /**
     * Test fetchCol with concatenation
     */
    public function fetchColVulnerable(string $id): array
    {
        // VULNERABLE: SQL injection via fetchCol()
        $sql = "SELECT name FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchCol($sql);
    }

    /**
     * Test fetchGroup with concatenation
     */
    public function fetchGroupVulnerable(string $id): array
    {
        // VULNERABLE: SQL injection via fetchGroup()
        $sql = "SELECT role, name FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchGroup($sql, [], PDO::FETCH_COLUMN);
    }

    /**
     * Test fetchObject with concatenation
     */
    public function fetchObjectVulnerable(string $id): object|false
    {
        // VULNERABLE: SQL injection via fetchObject()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchObject($sql);
    }

    /**
     * Test fetchObjects with concatenation
     */
    public function fetchObjectsVulnerable(string $id): array
    {
        // VULNERABLE: SQL injection via fetchObjects()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchObjects($sql);
    }

    /**
     * Test fetchOne with concatenation
     */
    public function fetchOneVulnerable(string $id): array|false
    {
        // VULNERABLE: SQL injection via fetchOne()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchOne($sql);
    }

    /**
     * Test fetchPairs with concatenation
     */
    public function fetchPairsVulnerable(string $id): array
    {
        // VULNERABLE: SQL injection via fetchPairs()
        $sql = "SELECT id, name FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchPairs($sql);
    }

    /**
     * Test fetchValue with concatenation
     */
    public function fetchValueVulnerable(string $id): mixed
    {
        // VULNERABLE: SQL injection via fetchValue()
        $sql = "SELECT name FROM users WHERE id = '" . $id . "'";

        return $this->pdo->fetchValue($sql);
    }

    // =========================================================================
    // ExtendedPdoInterface execute methods
    // =========================================================================

    /**
     * Test perform with concatenation
     */
    public function performVulnerable(string $id): array
    {
        // VULNERABLE: SQL injection via perform()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->perform($sql)->fetchAll();
    }

    /**
     * Test prepareWithValues with concatenation
     */
    public function prepareWithValuesVulnerable(string $table): array
    {
        // VULNERABLE: SQL injection via prepareWithValues()
        $sql = "SELECT * FROM " . $table . " WHERE id = :id";

        return $this->pdo->prepareWithValues($sql, ['id' => 1])->fetchAll();
    }

    // =========================================================================
    // ExtendedPdoInterface yield* methods (generators)
    // =========================================================================

    /**
     * Test yieldAll with concatenation
     *
     * @return \Generator<array>
     */
    public function yieldAllVulnerable(string $id): \Generator
    {
        // VULNERABLE: SQL injection via yieldAll()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->yieldAll($sql);
    }

    /**
     * Test yieldAssoc with concatenation
     *
     * @return \Generator<string, array>
     */
    public function yieldAssocVulnerable(string $id): \Generator
    {
        // VULNERABLE: SQL injection via yieldAssoc()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->yieldAssoc($sql);
    }

    /**
     * Test yieldCol with concatenation
     *
     * @return \Generator<mixed>
     */
    public function yieldColVulnerable(string $id): \Generator
    {
        // VULNERABLE: SQL injection via yieldCol()
        $sql = "SELECT name FROM users WHERE id = '" . $id . "'";

        return $this->pdo->yieldCol($sql);
    }

    /**
     * Test yieldObjects with concatenation
     *
     * @return \Generator<object>
     */
    public function yieldObjectsVulnerable(string $id): \Generator
    {
        // VULNERABLE: SQL injection via yieldObjects()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";

        return $this->pdo->yieldObjects($sql);
    }

    /**
     * Test yieldPairs with concatenation
     *
     * @return \Generator<mixed, mixed>
     */
    public function yieldPairsVulnerable(string $id): \Generator
    {
        // VULNERABLE: SQL injection via yieldPairs()
        $sql = "SELECT id, name FROM users WHERE id = '" . $id . "'";

        return $this->pdo->yieldPairs($sql);
    }
}
