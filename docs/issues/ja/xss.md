---
layout: default
title: XSS
lang: ja
---

# XSS (クロスサイトスクリプティング)

ユーザー入力が適切なエスケープなしにHTMLに出力される場合に検出されます。

```php
<?php
class GreetingResource extends ResourceObject
{
    public function onGet(string $name): static
    {
        // 脆弱: XSS
        $this->body['html'] = "<h1>Hello, {$name}!</h1>";

        return $this;
    }
}
```

## 修正方法

出力時に適切なエスケープを行ってください：

```php
<?php
class GreetingResource extends ResourceObject
{
    public function onGet(string $name): static
    {
        // 安全: HTMLエスケープ
        $this->body['html'] = "<h1>Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";

        return $this;
    }
}
```

Twigなどのテンプレートエンジンは自動エスケープを提供します。コンテキストに応じた適切なエスケープを使用してください（HTML、JavaScript、URL、CSS）。
