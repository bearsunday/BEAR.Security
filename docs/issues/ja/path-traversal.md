---
layout: default
nav_exclude: true
title: PathTraversal
lang: ja
---

# PathTraversal

ユーザー入力がファイルパスとして使用され、ディレクトリトラバーサル攻撃が可能な場合に検出されます。

```php
<?php
class FileResource extends ResourceObject
{
    public function onGet(string $filename): static
    {
        // 脆弱: パストラバーサル
        $this->body['content'] = file_get_contents("/var/www/files/" . $filename);

        return $this;
    }
}
```

## 修正方法

ファイル名を検証し、ベースディレクトリ外へのアクセスを防止してください：

```php
<?php
class FileResource extends ResourceObject
{
    private const BASE_DIR = '/var/www/files';

    public function onGet(string $filename): static
    {
        // 安全: basename でディレクトリトラバーサルを除去し、realpath で検証
        $basePath = realpath(self::BASE_DIR);
        $fullPath = realpath(self::BASE_DIR . '/' . basename($filename));

        if ($fullPath === false || !str_starts_with($fullPath, $basePath)) {
            throw new NotFoundException('File not found');
        }

        $this->body['content'] = file_get_contents($fullPath);

        return $this;
    }
}
```

ホワイトリスト方式や、ファイルIDをキーとしたルックアップも有効です。
