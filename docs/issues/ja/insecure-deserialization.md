---
layout: default
title: InsecureDeserialization
lang: ja
---

# InsecureDeserialization

ユーザー入力に対して `unserialize()` が使用される場合に検出されます。

```php
<?php
class SessionResource extends ResourceObject
{
    public function onPost(string $data): static
    {
        // 脆弱: 安全でないデシリアライゼーション
        $this->body['user'] = unserialize(base64_decode($data));

        return $this;
    }
}
```

## 修正方法

代わりにJSONを使用してください：

```php
<?php
class SessionResource extends ResourceObject
{
    public function onPost(string $data): static
    {
        // 安全: JSONを使用
        $this->body['user'] = json_decode(base64_decode($data), true, 512, JSON_THROW_ON_ERROR);

        return $this;
    }
}
```

`unserialize()` が必要な場合は、`allowed_classes` オプションで許可するクラスを制限してください：

```php
$data = unserialize($input, ['allowed_classes' => [User::class]]);
```
