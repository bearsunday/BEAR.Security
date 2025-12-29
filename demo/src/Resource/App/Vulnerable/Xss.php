<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use BEAR\Resource\ResourceObject;

/**
 * VULNERABLE: Direct HTML output without escaping
 *
 * Expected: TaintedHtml detection
 */
class Xss extends ResourceObject
{
    public function onGet(string $name): static
    {
        // VULNERABLE: XSS via direct HTML concatenation
        $this->body['html'] = '<h1>Hello, ' . $name . '</h1>';

        return $this;
    }

    public function onPost(string $message): static
    {
        // VULNERABLE: Direct echo without escaping
        echo '<div>' . $message . '</div>';

        return $this;
    }
}
