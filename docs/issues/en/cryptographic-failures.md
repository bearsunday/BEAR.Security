---
layout: default
title: CryptographicFailures
---

# CryptographicFailures

Emitted when weak or deprecated cryptographic algorithms are used.

```php
<?php
class HashResource extends ResourceObject
{
    public function onPost(string $password): static
    {
        // VULNERABLE: Weak hash algorithm
        $this->body['hash'] = md5($password);

        return $this;
    }
}
```

## How to fix

Use strong, modern algorithms:

```php
<?php
class HashResource extends ResourceObject
{
    public function onPost(string $password): static
    {
        // SAFE: Use password_hash for passwords
        $this->body['hash'] = password_hash($password, PASSWORD_ARGON2ID);

        return $this;
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}
```

For general hashing, use SHA-256 or SHA-3. For encryption, use AES-256-GCM.
