<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use BEAR\Resource\RenderInterface;
use BEAR\Resource\ResourceObject;

/**
 * SAFE: Using JsonRenderer for output
 *
 * Expected: No TaintedHtml (JSON encoding escapes HTML)
 *
 * Requires bear/resource with taint annotations
 */
class JsonOutput extends ResourceObject
{
    public function __construct(
        private RenderInterface $renderer,
    ) {
    }

    public function onGet(): static
    {
        $name = $_GET['name'] ?? '';

        // SAFE: JsonRenderer escapes via json_encode
        $this->body = ['name' => $name, 'greeting' => "Hello, {$name}"];

        return $this;
    }
}
