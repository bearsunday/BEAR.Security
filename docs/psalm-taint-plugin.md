# Psalm Taint Plugin for BEAR.Sunday

Psalm taint analysis plugin for BEAR.Sunday framework.

## Overview

BEAR.Sunday の `ResourceObject` は内部的に `call_user_func_array` を介して動的に実行されるため、Psalm の標準の taint analysis では `onGet`/`onPost` 等のメソッドパラメータが外部入力として認識されません。

このプラグインは、`ResourceObject` を継承したクラスの `on*` メソッドの全パラメータを自動的に taint source として登録し、E2E での脆弱性検出を可能にします。

## Configuration

`psalm.xml` にプラグインを追加:

```xml
<plugins>
    <pluginClass class="BEAR\Security\Psalm\ResourceTaintPlugin">
        <targets>
            <target>Page</target>
            <target>App</target>
        </targets>
    </pluginClass>
</plugins>
```

### Targets

`targets` で汚染源とするリソースタイプを指定できます:

- `Page` - `\Resource\Page\` 名前空間のリソース
- `App` - `\Resource\App\` 名前空間のリソース

デフォルトは両方が有効です。

## Usage

```bash
./vendor/bin/psalm --taint-analysis
```

### Detection Example

```php
class User extends ResourceObject
{
    public function onGet(string $id): static
    {
        // TaintedSql が検出される！
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
        // prepared statement で安全
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

このプラグインと組み合わせて使用する BEAR.Sunday エコシステムのパッケージには、taint annotation が必要です:

| Package | Annotations | Status |
|---------|-------------|--------|
| bear/resource | `@psalm-taint-source input` | 1.29.0+ |
| ray/media-query | `@psalm-taint-escape sql` | 1.0.2+ |
| madapaja/twig-module | `@psalm-taint-escape html` | 2.7.0+ |
| aura/sql | `@psalm-taint-sink sql`, `@psalm-taint-escape sql` | stub対応 |
| qiq/qiq | `@psalm-taint-escape html` | stub対応 |

aura/sql と qiq/qiq は正式リリースまで BEAR.Security 同梱の stub で対応しています。

## How It Works

1. `AfterFunctionLikeAnalysisInterface` フックで `on*` メソッドの解析後に介入
2. `ResourceObject` を継承したクラスかどうかを `classExtends` で判定
3. 対象メソッドの全パラメータに `TaintKindGroup::ALL_INPUT` を付与した `TaintSource` を生成
4. `taint_flow_graph->addSource()` でグラフに登録

これにより、`call_user_func_array` による動的ディスパッチの制限を回避し、メソッドパラメータからシンク（`PDO::query()` 等）までの taint flow を追跡できます。

## References

- [Psalm Taint Analysis](https://psalm.dev/docs/security_analysis/)
- [BEAR.Sunday Framework](https://bearsunday.github.io/)
