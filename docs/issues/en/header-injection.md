---
layout: default
title: HeaderInjection
---

# HeaderInjection

Emitted when user-controlled input is used in HTTP headers without proper sanitization.

```php
<?php
class RedirectResource extends ResourceObject
{
    public function onGet(string $url): static
    {
        // VULNERABLE: Header injection possible
        header('Location: ' . $url);

        return $this;
    }
}
```

## How to fix

Validate and sanitize header values, remove newlines:

```php
<?php
class RedirectResource extends ResourceObject
{
    public function onGet(string $url): static
    {
        // SAFE: Remove newlines and validate URL
        $safeUrl = str_replace(["\r", "\n"], '', $url);

        if (!filter_var($safeUrl, FILTER_VALIDATE_URL)) {
            throw new BadRequestException('Invalid URL');
        }

        header('Location: ' . $safeUrl);

        return $this;
    }
}
```
