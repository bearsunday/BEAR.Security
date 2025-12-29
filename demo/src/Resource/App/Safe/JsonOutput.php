<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

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
    public function onGet(string $name): static
    {
        // SAFE: JsonRenderer escapes via json_encode
        $this->body = ['name' => $name, 'greeting' => "Hello, {$name}"];

        return $this;
    }
}
