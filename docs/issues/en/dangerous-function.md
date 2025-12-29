---
layout: default
title: DangerousFunction
---

# DangerousFunction

Emitted when dangerous functions like `eval()`, `exec()`, or `system()` are used with user input.

```php
<?php
class CalculatorResource extends ResourceObject
{
    public function onGet(string $expression): static
    {
        // VULNERABLE: Code execution
        eval('$result = ' . $expression . ';');
        $this->body['result'] = $result;

        return $this;
    }
}
```

## How to fix

Avoid `eval()` entirely. Use safe alternatives:

```php
<?php
class CalculatorResource extends ResourceObject
{
    public function onGet(string $expression): static
    {
        // SAFE: Use a math parser library
        $parser = new MathParser();
        $this->body['result'] = $parser->evaluate($expression);

        return $this;
    }
}
```

For shell operations, use `escapeshellarg()` and `escapeshellcmd()`, or avoid shell commands entirely.
