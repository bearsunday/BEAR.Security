<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;

/**
 * VULNERABLE: Edge cases that SHOULD trigger TaintedSql
 *
 * These patterns test that taint analysis correctly detects
 * vulnerabilities even in complex scenarios.
 *
 * NOTE: Some patterns are NOT detected due to Psalm taint analysis limitations:
 * - Variable reassignment before concatenation (taint flow through variables)
 * - sprintf() formatting (Psalm doesn't track sprintf as taint propagation)
 * - Partial binding with $values (the escape annotation covers the whole call)
 *
 * These are known Psalm limitations, not issues with the stub.
 */
class AuraSqlEdgeCases extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    /**
     * Vulnerable: Direct concatenation in double-quoted string
     *
     * Expected: TaintedSql detected
     */
    public function onGet(string $name): static
    {
        $sql = "SELECT * FROM users WHERE name = '$name'";
        $this->body = $this->pdo->fetchAll($sql);

        return $this;
    }

    /**
     * Vulnerable: Heredoc with variable interpolation
     *
     * Expected: TaintedSql detected
     */
    public function onPost(string $id): static
    {
        $sql = <<<SQL
            SELECT * FROM users WHERE id = '{$id}'
        SQL;
        $this->body = $this->pdo->fetchAll($sql);

        return $this;
    }

    /**
     * Vulnerable: Concatenation operator with perform()
     *
     * Expected: TaintedSql detected
     */
    public function onPut(string $id): static
    {
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->pdo->perform($sql);

        return $this;
    }

    /**
     * Vulnerable: Concatenation with yield method
     *
     * Expected: TaintedSql detected
     */
    public function onPatch(string $id): static
    {
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->pdo->yieldAll($sql);

        return $this;
    }

    /**
     * Vulnerable: Direct interpolation in fetchOne
     *
     * Expected: TaintedSql detected
     */
    public function onDelete(string $name): static
    {
        $this->body = $this->pdo->fetchOne("SELECT * FROM users WHERE name = '$name'");

        return $this;
    }
}
