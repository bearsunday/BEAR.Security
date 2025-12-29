<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use BEAR\Resource\ResourceObject;
use Ray\MediaQuery\SqlQueryInterface;

/**
 * SAFE: Using prepared statements via MediaQuery
 *
 * Expected: No TaintedSql (values are escaped via prepared statements)
 *
 * Requires ray/media-query with taint annotations (PR #78)
 */
class SqlPrepared extends ResourceObject
{
    public function __construct(
        private SqlQueryInterface $sqlQuery,
    ) {
    }

    public function onGet(): static
    {
        $id = $_GET['id'] ?? '';

        // SAFE: MediaQuery uses prepared statements
        // The $id is bound as a parameter, not concatenated
        $this->body = $this->sqlQuery->getRow('user_by_id', ['id' => $id]);

        return $this;
    }

    public function onPost(): static
    {
        $name = $_POST['name'] ?? '';
        $email = $_POST['email'] ?? '';

        // SAFE: All values are bound as parameters
        $this->sqlQuery->exec('user_insert', ['name' => $name, 'email' => $email]);
        $this->body = ['status' => 'created'];

        return $this;
    }
}
