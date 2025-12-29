<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use BEAR\Resource\JsonRenderer;
use BEAR\Resource\ResourceObject;

/**
 * SAFE: Using JsonRenderer with actual echo output
 *
 * Expected: No TaintedHtml (JSON encoding escapes HTML)
 *
 * This test verifies that echoing JSON-rendered content is safe.
 * Requires bear/resource with taint annotations.
 */
class JsonRendererEcho extends ResourceObject
{
    public function __construct(
        private readonly JsonRenderer $renderer = new JsonRenderer(),
    ) {
    }

    public function onGet(string $name): static
    {
        // Set tainted data in body
        $this->body = ['name' => $name, 'greeting' => "Hello, {$name}"];

        // SAFE: JsonRenderer escapes via json_encode
        $json = $this->renderer->render($this);
        echo $json;

        return $this;
    }
}
