---
layout: default
title: WeakRandom
---

# WeakRandom

Emitted when cryptographically weak random functions are used for security-sensitive operations.

```php
<?php
class TokenResource extends ResourceObject
{
    public function onGet(): static
    {
        // VULNERABLE: Predictable random
        $this->body['token'] = md5(rand());

        return $this;
    }
}
```

## How to fix

Use cryptographically secure random functions:

```php
<?php
class TokenResource extends ResourceObject
{
    public function onGet(): static
    {
        // SAFE: Cryptographically secure random
        $this->body['token'] = bin2hex(random_bytes(32));

        return $this;
    }
}
```

Use `random_bytes()` or `random_int()` for security-sensitive randomness.
