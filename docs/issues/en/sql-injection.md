---
layout: default
title: SqlInjection
---

# SqlInjection

Emitted when user-controlled input can be passed into a SQL query without proper sanitization.

```php
<?php
class UserResource extends ResourceObject
{
    public function __construct(private PDO $pdo) {}

    public function onGet(string $id): static
    {
        // VULNERABLE: Direct string concatenation
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }
}
```

## How to fix

Use prepared statements with bound parameters:

```php
<?php
class UserResource extends ResourceObject
{
    public function __construct(private PDO $pdo) {}

    public function onGet(string $id): static
    {
        // SAFE: Using prepared statement
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $this->body = $stmt->fetchAll();

        return $this;
    }
}
```

Or use query builders like Aura.SqlQuery or Doctrine DBAL that handle escaping automatically.
