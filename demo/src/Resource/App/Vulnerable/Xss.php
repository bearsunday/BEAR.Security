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
    public function onGet(): static
    {
        $name = $_GET['name'] ?? '';

        // VULNERABLE: XSS via direct HTML concatenation
        $this->body['html'] = '<h1>Hello, ' . $name . '</h1>';

        return $this;
    }

    public function onPost(): static
    {
        $message = $_POST['message'] ?? '';

        // VULNERABLE: Direct echo without escaping
        echo '<div>' . $message . '</div>';

        return $this;
    }
}
