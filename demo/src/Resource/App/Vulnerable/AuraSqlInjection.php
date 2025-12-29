<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use Aura\Sql\ExtendedPdoInterface;
use BEAR\Resource\ResourceObject;

/**
 * VULNERABLE: Using Aura.Sql query()/exec()/prepare() with concatenation
 *
 * Expected: TaintedSql detection
 *
 * Aura.Sql's query(), exec(), and prepare() are taint sinks.
 * Direct concatenation of user input is detected.
 */
class AuraSqlInjection extends ResourceObject
{
    public function __construct(
        private ExtendedPdoInterface $pdo,
    ) {
    }

    public function onGet(): static
    {
        $id = $_GET['id'] ?? '';

        // VULNERABLE: SQL injection via query()
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }

    public function onPost(): static
    {
        $name = $_POST['name'] ?? '';

        // VULNERABLE: SQL injection via exec()
        $sql = "DELETE FROM users WHERE name = '" . $name . "'";
        $this->pdo->exec($sql);

        return $this;
    }

    public function onPut(): static
    {
        $table = $_GET['table'] ?? '';

        // VULNERABLE: SQL injection via prepare() with concatenation
        $sql = "SELECT * FROM " . $table . " WHERE id = :id";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(['id' => 1]);
        $this->body = $stmt->fetchAll();

        return $this;
    }
}
