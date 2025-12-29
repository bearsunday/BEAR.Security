---
layout: default
title: CSRF
lang: ja
---

# CSRF (クロスサイトリクエストフォージェリ)

状態を変更するアクションにCSRF保護がない場合に検出されます。

```php
<?php
class TransferResource extends ResourceObject
{
    public function onPost(string $to, int $amount): static
    {
        // 脆弱: CSRFトークンなし
        $this->transferMoney($to, $amount);
        $this->body = ['status' => 'transferred'];

        return $this;
    }
}
```

## 修正方法

CSRFトークンを実装してリクエストを検証してください：

```php
<?php
class TransferResource extends ResourceObject
{
    public function __construct(
        private CsrfTokenManager $csrf
    ) {}

    public function onPost(string $to, int $amount, string $token): static
    {
        // 安全: CSRFトークンを検証
        if (!$this->csrf->isTokenValid($token)) {
            throw new ForbiddenException('Invalid CSRF token');
        }

        $this->transferMoney($to, $amount);
        $this->body = ['status' => 'transferred'];

        return $this;
    }
}
```

SameSite Cookieの設定やフレームワーク提供のCSRF保護機能の使用も検討してください。
