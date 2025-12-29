---
layout: default
nav_exclude: true
title: OpenRedirect
---

# OpenRedirect

Emitted when user-controlled input determines redirect destinations without validation.

```php
<?php
class LoginResource extends ResourceObject
{
    public function onPost(string $username, string $password, string $returnUrl): static
    {
        $this->authenticate($username, $password);

        // VULNERABLE: Open redirect
        header('Location: ' . $returnUrl);

        return $this;
    }
}
```

## How to fix

Use a whitelist of allowed domains or only allow relative URLs:

```php
<?php
class LoginResource extends ResourceObject
{
    private const ALLOWED_HOSTS = ['example.com', 'www.example.com'];

    public function onPost(string $username, string $password, string $returnUrl): static
    {
        $this->authenticate($username, $password);

        // SAFE: Validate redirect destination
        $parsed = parse_url($returnUrl);
        $host = $parsed['host'] ?? null;

        if ($host !== null && !in_array($host, self::ALLOWED_HOSTS, true)) {
            $returnUrl = '/';
        }

        header('Location: ' . $returnUrl);

        return $this;
    }
}
```
