---
layout: default
title: SessionSecurity
lang: ja
---

# SessionSecurity

セッション設定が安全でない場合に検出されます。

```php
<?php
// 脆弱: セッション設定が安全でない
ini_set('session.cookie_httponly', '0');
ini_set('session.cookie_secure', '0');
ini_set('session.use_strict_mode', '0');
session_start();
```

## 修正方法

セッションを安全に設定してください：

```php
<?php
// 安全: セキュアなセッション設定
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');

session_start();

// ログイン後にセッションIDを再生成
session_regenerate_id(true);
```
