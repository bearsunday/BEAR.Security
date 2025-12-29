---
layout: default
nav_exclude: true
title: CryptographicFailures
lang: ja
---

# CryptographicFailures

脆弱または非推奨の暗号アルゴリズムが使用されている場合に検出されます。

```php
<?php
class HashResource extends ResourceObject
{
    public function onPost(string $password): static
    {
        // 脆弱: 弱いハッシュアルゴリズム
        $this->body['hash'] = md5($password);

        return $this;
    }
}
```

## 修正方法

強力で現代的なアルゴリズムを使用してください：

```php
<?php
class HashResource extends ResourceObject
{
    public function onPost(string $password): static
    {
        // 安全: password_hash を使用
        $this->body['hash'] = password_hash($password, PASSWORD_ARGON2ID);

        return $this;
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}
```

一般的なハッシュにはSHA-256またはSHA-3を、暗号化にはAES-256-GCMを使用してください。
