---
layout: default
title: RemoteFileInclusion
---

# RemoteFileInclusion

Emitted when user-controlled input is used in file inclusion functions that can load remote files.

```php
<?php
class TemplateResource extends ResourceObject
{
    public function onGet(string $template): static
    {
        // VULNERABLE: Remote file inclusion
        include $template;

        return $this;
    }
}
```

## How to fix

Use a whitelist of allowed files and validate paths:

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
        // SAFE: Whitelist approach
        if (!isset(self::ALLOWED_TEMPLATES[$template])) {
            throw new NotFoundException('Template not found');
        }

        include self::ALLOWED_TEMPLATES[$template];

        return $this;
    }
}
```

Also disable `allow_url_include` in php.ini.
