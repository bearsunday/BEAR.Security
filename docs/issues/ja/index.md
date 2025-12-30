---
layout: default
nav_exclude: true
title: 検出タイプ
lang: ja
---

# 検出タイプ

## インジェクション

- [SqlInjection](sql-injection) - SQLインジェクション
- [CommandInjection](command-injection) - コマンドインジェクション
- [XSS](xss) - クロスサイトスクリプティング
- [HeaderInjection](header-injection) - HTTPヘッダーインジェクション
- [XXE](xxe) - XML外部エンティティ参照

## ファイル・パス

- [PathTraversal](path-traversal) - パストラバーサル / ローカルファイルインクルージョン
- [RemoteFileInclusion](remote-file-inclusion) - リモートファイルインクルージョン

## 認証・セッション

- [CSRF](csrf) - クロスサイトリクエストフォージェリ
- [SessionSecurity](session-security) - セッションセキュリティ
- [OpenRedirect](open-redirect) - オープンリダイレクト

## 暗号

- [CryptographicFailures](cryptographic-failures) - 脆弱な暗号
- [WeakRandom](weak-random) - 脆弱な乱数生成

## その他

- [InsecureDeserialization](insecure-deserialization) - 安全でないデシリアライゼーション
- [DangerousFunction](dangerous-function) - 危険な関数の使用
