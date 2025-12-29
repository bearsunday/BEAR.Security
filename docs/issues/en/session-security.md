---
layout: default
title: SessionSecurity
---

# SessionSecurity

Emitted when session configuration is insecure.

```php
<?php
// VULNERABLE: Insecure session settings
ini_set('session.cookie_httponly', '0');
ini_set('session.cookie_secure', '0');
ini_set('session.use_strict_mode', '0');
session_start();
```

## How to fix

Configure sessions securely:

```php
<?php
// SAFE: Secure session configuration
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');

session_start();

// Regenerate ID after login
session_regenerate_id(true);
```
