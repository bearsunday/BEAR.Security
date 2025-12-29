---
layout: default
nav_exclude: true
title: XXE
---

# XXE (XML External Entity)

Emitted when XML parsing allows external entity loading, enabling file disclosure or SSRF.

```php
<?php
class XmlResource extends ResourceObject
{
    public function onPost(string $xml): static
    {
        // VULNERABLE: External entities enabled
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $this->body = $doc->saveXML();

        return $this;
    }
}
```

## How to fix

Disable external entity loading:

```php
<?php
class XmlResource extends ResourceObject
{
    public function onPost(string $xml): static
    {
        // SAFE: External entities disabled
        $doc = new DOMDocument();
        $doc->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS);
        $this->body = $doc->saveXML();

        return $this;
    }
}
```

**Note:** In PHP 8.0+, external entity loading is disabled by default. `LIBXML_NONET` prevents network access but doesn't affect local file access - for complete protection, rely on PHP's default behavior. Adding `LIBXML_NONET` makes the intent explicit. Consider using JSON instead of XML when possible.
