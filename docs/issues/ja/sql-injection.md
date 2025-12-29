---
layout: default
title: SqlInjection
lang: ja
---

# SqlInjection

ユーザー入力がSQLクエリに直接連結される場合に検出されます。

```php
<?php
class UserResource extends ResourceObject
{
    public function __construct(private PDO $pdo) {}

    public function onGet(string $id): static
    {
        // 脆弱: 文字列連結によるSQLインジェクション
        $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
        $this->body = $this->pdo->query($sql)->fetchAll();

        return $this;
    }
}
```

## 修正方法

プリペアドステートメントとバインドパラメータを使用してください：

```php
<?php
class UserResource extends ResourceObject
{
    public function __construct(private PDO $pdo) {}

    public function onGet(string $id): static
    {
        // 安全: プリペアドステートメント
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $this->body = $stmt->fetchAll();

        return $this;
    }
}
```

Aura.SqlQueryやDoctrine DBALなどのクエリビルダも自動的にエスケープを処理します。
