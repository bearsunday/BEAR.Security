---
layout: default
nav_exclude: true
title: InsecureDeserialization
---

# InsecureDeserialization

Emitted when `unserialize()` is called on user-controlled input without restricting allowed classes.

```php
<?php
class DataResource extends ResourceObject
{
    public function onPost(string $data): static
    {
        // VULNERABLE: Arbitrary class instantiation
        $this->body = unserialize(base64_decode($data));

        return $this;
    }
}
```

## How to fix

Always use `allowed_classes` option or use JSON instead:

```php
<?php
class DataResource extends ResourceObject
{
    public function onPost(string $data): static
    {
        // SAFE: Restrict allowed classes
        $this->body = unserialize(
            base64_decode($data),
            ['allowed_classes' => false]
        );

        return $this;
    }
}
```

Prefer JSON for data serialization:

```php
$this->body = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
```
