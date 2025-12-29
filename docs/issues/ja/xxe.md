---
layout: default
nav_exclude: true
title: XXE
lang: ja
---

# XXE (XML外部エンティティ参照)

XMLパーサーが外部エンティティを処理するよう設定されている場合に検出されます。

```php
<?php
class XmlResource extends ResourceObject
{
    public function onPost(string $xml): static
    {
        // 脆弱: XXE攻撃が可能
        $doc = simplexml_load_string($xml);
        $this->body['data'] = (array) $doc;

        return $this;
    }
}
```

## 修正方法

外部エンティティの読み込みを無効にしてください：

```php
<?php
class XmlResource extends ResourceObject
{
    public function onPost(string $xml): static
    {
        // 安全: 外部エンティティを無効化
        $doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOBLANKS);
        $this->body['data'] = (array) $doc;

        return $this;
    }
}
```

デフォルトで外部エンティティは無効化されていますが、`LIBXML_NONET` を明示することで意図を明確にできます。可能であればXMLの代わりにJSONを使用することを検討してください。
