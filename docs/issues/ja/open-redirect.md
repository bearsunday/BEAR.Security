---
layout: default
title: OpenRedirect
lang: ja
---

# OpenRedirect

ユーザー入力がリダイレクト先として検証なしに使用される場合に検出されます。

```php
<?php
class LoginResource extends ResourceObject
{
    public function onPost(string $username, string $password, string $returnUrl): static
    {
        $this->authenticate($username, $password);

        // 脆弱: オープンリダイレクト
        header('Location: ' . $returnUrl);

        return $this;
    }
}
```

## 修正方法

許可されたドメインのホワイトリストを使用するか、相対URLのみを許可してください：

```php
<?php
class LoginResource extends ResourceObject
{
    private const ALLOWED_HOSTS = ['example.com', 'www.example.com'];

    public function onPost(string $username, string $password, string $returnUrl): static
    {
        $this->authenticate($username, $password);

        // 安全: リダイレクト先を検証
        $parsed = parse_url($returnUrl);
        $host = $parsed['host'] ?? null;

        if ($host !== null && !in_array($host, self::ALLOWED_HOSTS, true)) {
            $returnUrl = '/';
        }

        header('Location: ' . $returnUrl);

        return $this;
    }
}
```
