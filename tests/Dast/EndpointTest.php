<?php

declare(strict_types=1);

namespace BEAR\Security\Dast;

use PHPUnit\Framework\TestCase;

class EndpointTest extends TestCase
{
    public function testConstruct(): void
    {
        $endpoint = new Endpoint('/user', 'GET', [
            'id' => ['type' => 'string', 'required' => true],
            'name' => ['type' => 'string', 'required' => false, 'default' => 'test'],
        ]);

        $this->assertSame('/user', $endpoint->uri);
        $this->assertSame('GET', $endpoint->method);
        $this->assertCount(2, $endpoint->parameters);
    }

    public function testGetRequiredParameters(): void
    {
        $endpoint = new Endpoint('/user', 'POST', [
            'id' => ['type' => 'int', 'required' => true],
            'name' => ['type' => 'string', 'required' => true],
            'age' => ['type' => 'int', 'required' => false],
        ]);

        $required = $endpoint->getRequiredParameters();

        $this->assertSame(['id', 'name'], $required);
    }

    public function testGetParameterNames(): void
    {
        $endpoint = new Endpoint('/user', 'GET', [
            'id' => ['type' => 'string', 'required' => true],
            'type' => ['type' => 'string', 'required' => false],
        ]);

        $names = $endpoint->getParameterNames();

        $this->assertSame(['id', 'type'], $names);
    }

    public function testHasParameters(): void
    {
        $withParams = new Endpoint('/user', 'GET', [
            'id' => ['type' => 'string', 'required' => true],
        ]);
        $withoutParams = new Endpoint('/index', 'GET');

        $this->assertTrue($withParams->hasParameters());
        $this->assertFalse($withoutParams->hasParameters());
    }

    public function testToString(): void
    {
        $endpoint = new Endpoint('/user', 'GET', [
            'id' => ['type' => 'string', 'required' => true],
            'name' => ['type' => 'string', 'required' => false],
        ]);

        $string = (string) $endpoint;

        $this->assertSame('GET /user(string $id, ?string $name)', $string);
    }

    public function testToStringWithoutParams(): void
    {
        $endpoint = new Endpoint('/index', 'GET');

        $string = (string) $endpoint;

        $this->assertSame('GET /index', $string);
    }
}
