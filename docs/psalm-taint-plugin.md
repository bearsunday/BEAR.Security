# Psalm Taint Plugin for BEAR.Sunday

Detects security vulnerabilities in BEAR.Sunday applications through static taint analysis.

## Installation

```bash
composer require --dev bear/security
```

## Configuration

Add to your `psalm.xml`:

```xml
<?xml version="1.0"?>
<psalm
    errorLevel="2"
    runTaintAnalysis="true"
>
    <projectFiles>
        <directory name="src"/>
    </projectFiles>
    <plugins>
        <pluginClass class="BEAR\Security\Psalm\ResourceTaintPlugin"/>
    </plugins>
</psalm>
```

## Usage

```bash
./vendor/bin/psalm --taint-analysis
```

## What It Detects

| Type | Description |
|------|-------------|
| TaintedSql | SQL injection via unsanitized input |
| TaintedHtml | XSS via unescaped output |
| TaintedShell | Command injection via shell_exec/exec |
| TaintedSSRF | Server-side request forgery |

## Examples

### Vulnerable (detected)

```php
class User extends ResourceObject
{
    public function onGet(string $id): static
    {
        // TaintedSql detected!
        $sql = "SELECT * FROM users WHERE id = '$id'";
        $this->pdo->query($sql);
        return $this;
    }
}
```

### Safe (no errors)

```php
class User extends ResourceObject
{
    public function onGet(string $id): static
    {
        // Safe - prepared statement
        $this->pdo->perform(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );
        return $this;
    }
}
```

## Supported Packages

| Package | Version |
|---------|---------|
| bear/resource | 1.29.0+ |
| ray/media-query | 1.0.2+ |
| madapaja/twig-module | 2.7.0+ |
| aura/sql | stub included |
| qiq/qiq | stub included |

## References

- [Psalm Taint Analysis](https://psalm.dev/docs/security_analysis/)
- [BEAR.Sunday Framework](https://bearsunday.github.io/)
