---
layout: default
title: DangerousFunction
lang: ja
---

# DangerousFunction

`eval()` や `create_function()` など、危険な関数の使用が検出された場合に発生します。

```php
<?php
class CalcResource extends ResourceObject
{
    public function onGet(string $expression): static
    {
        // 脆弱: eval の使用
        eval('$result = ' . $expression . ';');
        $this->body['result'] = $result;

        return $this;
    }
}
```

## 修正方法

これらの関数を完全に避け、安全な代替手段を使用してください：

```php
<?php
class CalcResource extends ResourceObject
{
    public function onGet(float $a, float $b, string $op): static
    {
        // 安全: ホワイトリスト方式
        $this->body['result'] = match ($op) {
            'add' => $a + $b,
            'sub' => $a - $b,
            'mul' => $a * $b,
            'div' => $b !== 0.0 ? $a / $b : null,
            default => throw new BadRequestException('Unknown operator'),
        };

        return $this;
    }
}
```

`eval()` は事実上あらゆるPHPコードを実行できるため、絶対に避けてください。
