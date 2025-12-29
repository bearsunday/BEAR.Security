---
layout: default
nav_exclude: true
title: XSS
---

# XSS (Cross-Site Scripting)

Emitted when user-controlled input is output to HTML without proper escaping, allowing malicious scripts to be injected.

```php
<?php
class GreetingResource extends ResourceObject
{
    public function onGet(string $name): static
    {
        // VULNERABLE: Direct output without escaping
        $this->body['html'] = '<h1>Hello, ' . $name . '</h1>';

        return $this;
    }
}
```

## How to fix

Always escape output using `htmlspecialchars()` or a template engine with auto-escaping:

```php
<?php
class GreetingResource extends ResourceObject
{
    public function onGet(string $name): static
    {
        // SAFE: Escaped output
        $escaped = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        $this->body['html'] = '<h1>Hello, ' . $escaped . '</h1>';

        return $this;
    }
}
```

Or use Twig/Qiq templates which auto-escape by default.
