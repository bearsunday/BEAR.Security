# Psalm Taint Plugin for BEAR.Sunday

Psalm taint analysis plugin for BEAR.Sunday framework.

## Overview

BEAR.Sunday's `ResourceObject` is dynamically invoked via `call_user_func_array`, which prevents Psalm's standard taint analysis from recognizing `onGet`/`onPost` method parameters as external input.

This plugin automatically registers all parameters of `on*` methods in `ResourceObject` subclasses as taint sources, enabling end-to-end vulnerability detection.

## Installation

Install BEAR.Security:

```bash
composer require --dev bear/security
```

## Configuration

Add the following to your `psalm.xml`:

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
        <pluginClass class="BEAR\Security\Psalm\ResourceTaintPlugin">
            <targets>
                <target>Page</target>
                <target>App</target>
            </targets>
        </pluginClass>
    </plugins>
</psalm>
```

### Targets

Use `targets` to specify which resource types to treat as taint sources:

- `Page` - Resources in `\Resource\Page\` namespace
- `App` - Resources in `\Resource\App\` namespace

Both are enabled by default.

## Usage

Run taint analysis:

```bash
./vendor/bin/psalm --taint-analysis
```

### Detection Example

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

### Safe Pattern

```php
class User extends ResourceObject
{
    public function onGet(string $id): static
    {
        // Safe with prepared statement
        $this->pdo->perform(
            'SELECT * FROM users WHERE id = :id',
            ['id' => $id]
        );

        return $this;
    }
}
```

## Vulnerable Patterns

| File | Vulnerability | Detection |
|------|--------------|-----------|
| SqlInjection.php | PDO SQL injection | TaintedSql |
| AuraSqlInjection.php | Aura.Sql query/exec/prepare | TaintedSql |
| MethodParamInjection.php | Method parameter SQL injection | TaintedSql |
| Xss.php | Unescaped HTML output | TaintedHtml |
| ShellInjection.php | shell_exec/exec | TaintedShell |
| Ssrf.php | file_get_contents/curl | TaintedFile, TaintedSSRF |

## Safe Patterns

| File | Pattern | Result |
|------|---------|--------|
| SqlPrepared.php | MediaQuery prepared statements | No errors |
| AuraSqlPrepared.php | Aura.Sql perform/fetchAll/quote | No errors |
| MethodParamPrepared.php | Method params + prepared statements | No errors |
| HtmlEscaped.php | Qiq escape helpers | No errors |
| QiqEscapedEcho.php | Qiq escape + echo | No errors |
| JsonOutput.php | JsonRenderer | No errors |
| JsonRendererEcho.php | JsonRenderer + echo | No errors |
| TwigEscaped.php | Twig autoescape | No errors |

## Required Package Annotations

The following BEAR.Sunday ecosystem packages require taint annotations to work with this plugin:

| Package | Annotations | Status |
|---------|-------------|--------|
| bear/resource | `@psalm-taint-source input` | 1.29.0+ |
| ray/media-query | `@psalm-taint-escape sql` | 1.0.2+ |
| madapaja/twig-module | `@psalm-taint-escape html` | 2.7.0+ |
| aura/sql | `@psalm-taint-sink sql`, `@psalm-taint-escape sql` | stub included |
| qiq/qiq | `@psalm-taint-escape html` | stub included |

For aura/sql and qiq/qiq, BEAR.Security includes stubs until official releases.

## How It Works

1. Hooks into `on*` method analysis via `AfterFunctionLikeAnalysisInterface`
2. Checks if the class extends `ResourceObject` using `classExtends`
3. Creates `TaintSource` with `TaintKindGroup::ALL_INPUT` for all method parameters
4. Registers sources via `taint_flow_graph->addSource()`

This bypasses the `call_user_func_array` dynamic dispatch limitation and tracks taint flow from method parameters to sinks (e.g., `PDO::query()`).

## References

- [Psalm Taint Analysis](https://psalm.dev/docs/security_analysis/)
- [BEAR.Sunday Framework](https://bearsunday.github.io/)
