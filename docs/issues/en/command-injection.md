---
layout: default
nav_exclude: true
title: CommandInjection
---

# CommandInjection

Emitted when user-controlled input can be passed into a shell command without proper sanitization.

```php
<?php
class PingResource extends ResourceObject
{
    public function onGet(string $host): static
    {
        // VULNERABLE: Direct shell execution
        $this->body['result'] = shell_exec('ping -c 1 ' . $host);

        return $this;
    }
}
```

## How to fix

Use `escapeshellarg()` to escape arguments, or avoid shell commands entirely:

```php
<?php
class PingResource extends ResourceObject
{
    public function onGet(string $host): static
    {
        // SAFE: Escaped argument
        $this->body['result'] = shell_exec('ping -c 1 ' . escapeshellarg($host));

        return $this;
    }
}
```

Better yet, use PHP native functions instead of shell commands when possible.
