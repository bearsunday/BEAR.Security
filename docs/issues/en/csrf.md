---
layout: default
title: CSRF
---

# CSRF (Cross-Site Request Forgery)

Emitted when state-changing operations lack CSRF token validation.

```php
<?php
class TransferResource extends ResourceObject
{
    public function onPost(string $to, int $amount): static
    {
        // VULNERABLE: No CSRF protection
        $this->transferMoney($to, $amount);
        $this->body = ['status' => 'transferred'];

        return $this;
    }
}
```

## How to fix

Validate CSRF tokens on all state-changing requests:

```php
<?php
class TransferResource extends ResourceObject
{
    public function __construct(
        private CsrfTokenManager $csrf
    ) {}

    public function onPost(string $to, int $amount, string $token): static
    {
        // SAFE: CSRF token validated
        if (!$this->csrf->isTokenValid($token)) {
            throw new ForbiddenException('Invalid CSRF token');
        }

        $this->transferMoney($to, $amount);
        $this->body = ['status' => 'transferred'];

        return $this;
    }
}
```

Use SameSite cookies and consider using framework-provided CSRF protection.
