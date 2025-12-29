---
layout: default
nav_exclude: true
title: WeakRandom
lang: ja
---

# WeakRandom

セキュリティに関わる操作で暗号学的に弱い乱数関数が使用されている場合に検出されます。

```php
<?php
class TokenResource extends ResourceObject
{
    public function onGet(): static
    {
        // 脆弱: 予測可能な乱数
        $this->body['token'] = md5(rand());

        return $this;
    }
}
```

## 修正方法

暗号学的に安全な乱数関数を使用してください：

```php
<?php
class TokenResource extends ResourceObject
{
    public function onGet(): static
    {
        // 安全: 暗号学的に安全な乱数
        $this->body['token'] = bin2hex(random_bytes(32));

        return $this;
    }
}
```

セキュリティに関わる乱数生成には `random_bytes()` または `random_int()` を使用してください。
