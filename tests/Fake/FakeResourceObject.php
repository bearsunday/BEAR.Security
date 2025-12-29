<?php

declare(strict_types=1);

namespace BEAR\Security\Fake;

use ArrayObject;

/**
 * @extends ArrayObject<string, mixed>
 *
 * @property int $code
 * @property array<string, string> $headers
 * @property mixed $body
 */
final class FakeResourceObject extends ArrayObject
{
    public int $code = 200;

    /** @var array<string, string> */
    public array $headers = [];

    /** @var mixed */
    public $body = '';

    public function __toString(): string
    {
        return (string) $this->body;
    }
}
