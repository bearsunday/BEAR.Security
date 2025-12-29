<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use BEAR\Resource\ResourceObject;
use Qiq\Helper\Html\Escape;

/**
 * SAFE: Using Qiq's escape helper with actual echo output
 *
 * Expected: No TaintedHtml (Qiq h() escapes HTML)
 *
 * This test verifies that echoing Qiq-escaped content is safe.
 * Requires qiq/qiq with taint annotations.
 */
class QiqEscapedEcho extends ResourceObject
{
    public function __construct(
        private Escape $escape,
    ) {
    }

    public function onGet(string $name): static
    {
        // SAFE: Qiq's h() escapes HTML, then echo should be safe
        $escaped = $this->escape->h($name);
        echo '<h1>Hello, ' . $escaped . '</h1>';

        return $this;
    }

    public function onPost(string $comment): static
    {
        // SAFE: Multiple escape methods
        $escapedHtml = $this->escape->h($comment);
        $escapedAttr = $this->escape->a($comment);

        echo '<div class="comment" data-raw="' . $escapedAttr . '">' . $escapedHtml . '</div>';

        return $this;
    }
}
