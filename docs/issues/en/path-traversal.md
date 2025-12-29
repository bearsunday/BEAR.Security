---
layout: default
nav_exclude: true
title: PathTraversal
---

# PathTraversal

Emitted when user-controlled input can be used to access files outside the intended directory.

```php
<?php
class FileResource extends ResourceObject
{
    public function onGet(string $filename): static
    {
        // VULNERABLE: Path traversal possible
        $this->body['content'] = file_get_contents('/uploads/' . $filename);

        return $this;
    }
}
```

## How to fix

Use `basename()` to strip directory components and validate the path:

```php
<?php
class FileResource extends ResourceObject
{
    public function onGet(string $filename): static
    {
        // SAFE: Only filename, no path components
        $safeName = basename($filename);
        $path = '/uploads/' . $safeName;

        // Verify path stays within allowed directory
        $realPath = realpath($path);
        if ($realPath === false || !str_starts_with($realPath, '/uploads/')) {
            throw new BadRequestException('Invalid file');
        }

        $this->body['content'] = file_get_contents($realPath);

        return $this;
    }
}
```
