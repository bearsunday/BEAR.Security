---
layout: default
title: RemoteFileInclusion
lang: ja
---

# RemoteFileInclusion

ユーザー入力がリモートファイルを読み込み可能なファイルインクルード関数で使用される場合に検出されます。

```php
<?php
class TemplateResource extends ResourceObject
{
    public function onGet(string $template): static
    {
        // 脆弱: リモートファイルインクルージョン
        include $template;

        return $this;
    }
}
```

## 修正方法

許可されたファイルのホワイトリストを使用し、パスを検証してください：

```php
<?php
class TemplateResource extends ResourceObject
{
    private const ALLOWED_TEMPLATES = [
        'header' => '/templates/header.php',
        'footer' => '/templates/footer.php',
    ];

    public function onGet(string $template): static
    {
        // 安全: ホワイトリスト方式
        if (!isset(self::ALLOWED_TEMPLATES[$template])) {
            throw new NotFoundException('Template not found');
        }

        include self::ALLOWED_TEMPLATES[$template];

        return $this;
    }
}
```

また、php.iniで `allow_url_include` を無効にしてください。
