<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Safe;

use BEAR\Resource\ResourceObject;
use Twig\Environment;

/**
 * SAFE: Using Twig template engine for HTML output
 *
 * Expected: No TaintedHtml (Twig autoescapes by default)
 *
 * Requires madapaja/twig-module with taint annotations
 */
class TwigEscaped extends ResourceObject
{
    public function __construct(
        private Environment $twig,
    ) {
    }

    public function onGet(string $name): static
    {
        // SAFE: Twig autoescapes by default
        // {{ name }} in template will be escaped
        $this->body['html'] = $this->twig->render('greeting.html.twig', ['name' => $name]);

        return $this;
    }
}
