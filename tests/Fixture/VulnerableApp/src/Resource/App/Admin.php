<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;
use PDO;

/**
 * Vulnerabilities that require AI to detect (business logic flaws)
 */
class Admin extends ResourceObject
{
    public function __construct(
        private PDO $pdo,
    ) {
    }

    /**
     * AI-ONLY: Insecure Direct Object Reference (IDOR)
     * The user can access any user's data by changing the ID
     * SAST cannot detect this - requires understanding of authorization context
     */
    public function onGet(string $userId): static
    {
        // Looks safe but missing authorization check
        // Should verify: $this->session->getUserId() === $userId
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $this->body = $stmt->fetch();

        return $this;
    }

    /**
     * AI-ONLY: Mass Assignment Vulnerability
     * User can set 'role' field to 'admin' through request
     * SAST cannot understand the business logic danger
     */
    public function onPut(string $userId, array $data): static
    {
        // Looks like safe prepared statement, but...
        // 'role' field should not be user-controllable
        // Allowed fields whitelist prevents SQL injection via field names
        $allowedFields = ['name', 'email', 'role', 'status'];
        $fields = [];
        $values = [];
        foreach ($data as $key => $value) {
            if (in_array($key, $allowedFields, true)) {
                $fields[] = "{$key} = ?";
                $values[] = $value;
            }
        }
        if ($fields === []) {
            return $this;
        }
        $values[] = $userId;

        $sql = 'UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = ?';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($values);

        return $this;
    }

    /**
     * AI-ONLY: Race Condition in Balance Transfer
     * Two simultaneous requests can overdraw the account
     * Requires understanding of concurrent execution
     */
    public function onPost(string $fromId, string $toId, int $amount): static
    {
        // Check balance
        $stmt = $this->pdo->prepare('SELECT balance FROM accounts WHERE id = ?');
        $stmt->execute([$fromId]);
        $balance = $stmt->fetchColumn();

        // Time-of-check to time-of-use (TOCTOU) vulnerability
        if ($balance >= $amount) {
            // Another request could execute between check and update
            $this->pdo->prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?')
                ->execute([$amount, $fromId]);
            $this->pdo->prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?')
                ->execute([$amount, $toId]);
        }

        return $this;
    }
}
