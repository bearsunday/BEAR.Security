---
layout: default
title: CommandInjection
lang: ja
---

# CommandInjection

ユーザー入力がシェルコマンドに直接渡される場合に検出されます。

```php
<?php
class PingResource extends ResourceObject
{
    public function onGet(string $host): static
    {
        // 脆弱: コマンドインジェクション
        $this->body['result'] = shell_exec("ping -c 1 " . $host);

        return $this;
    }
}
```

## 修正方法

`escapeshellarg()` でエスケープするか、できればシェルコマンドを避けてください：

```php
<?php
class PingResource extends ResourceObject
{
    public function onGet(string $host): static
    {
        // 安全: escapeshellarg でエスケープ
        $this->body['result'] = shell_exec("ping -c 1 " . escapeshellarg($host));

        return $this;
    }
}
```

可能であれば、PHPのネイティブ関数やライブラリを使用してシェルコマンドを完全に避けることを推奨します。
