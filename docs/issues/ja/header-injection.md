---
layout: default
nav_exclude: true
title: HeaderInjection
lang: ja
---

# HeaderInjection

ユーザー入力がHTTPヘッダーに直接使用される場合に検出されます。

```php
<?php
class DownloadResource extends ResourceObject
{
    public function onGet(string $filename): static
    {
        // 脆弱: ヘッダーインジェクション
        header('Content-Disposition: attachment; filename=' . $filename);

        return $this;
    }
}
```

## 修正方法

ヘッダー値を検証し、改行文字を削除またはエンコードしてください：

```php
<?php
class DownloadResource extends ResourceObject
{
    public function onGet(string $filename): static
    {
        // 安全: 改行を削除してエンコード
        $safeFilename = str_replace(["\r", "\n"], '', $filename);
        $safeFilename = rawurlencode($safeFilename);

        header('Content-Disposition: attachment; filename="' . $safeFilename . '"');

        return $this;
    }
}
```

`header()` 関数は改行文字を含むヘッダーを拒否しますが、明示的な検証を行うことを推奨します。
