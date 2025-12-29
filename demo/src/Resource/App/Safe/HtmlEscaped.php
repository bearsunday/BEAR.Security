<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use BEAR\Resource\ResourceObject;
use Qiq\Helper\Html\Escape;

/**
 * SAFE: Using Qiq's escape helper for HTML output
 *
 * Expected: No TaintedHtml (values are escaped via Qiq)
 *
 * Requires qiq/qiq with taint annotations
 */
class HtmlEscaped extends ResourceObject
{
    public function __construct(
        private Escape $escape,
    ) {
    }

    public function onGet(): static
    {
        $name = $_GET['name'] ?? '';

        // SAFE: Qiq's h() escapes HTML special characters
        $this->body['html'] = '<h1>Hello, ' . $this->escape->h($name) . '</h1>';

        return $this;
    }

    public function onPost(): static
    {
        $url = $_POST['url'] ?? '';

        // SAFE: Qiq's u() escapes URL
        $this->body['link'] = '<a href="' . $this->escape->u($url) . '">Link</a>';

        return $this;
    }
}
