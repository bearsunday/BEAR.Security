<?php

declare(strict_types=1);

namespace BEAR\Security\Dast;

/**
 * DTO representing a discovered endpoint with its parameters
 */
final class Endpoint
{
    /**
     * @param string $uri      Resource URI (e.g., "/user", "/posts")
     * @param string $method   HTTP method (GET, POST, PUT, PATCH, DELETE)
     * @param array<string, array{type: string, required: bool, default?: mixed}> $parameters
     */
    public function __construct(
        public readonly string $uri,
        public readonly string $method,
        public readonly array $parameters = [],
    ) {
    }

    /**
     * Get required parameter names
     *
     * @return string[]
     */
    public function getRequiredParameters(): array
    {
        $required = [];
        foreach ($this->parameters as $name => $info) {
            if ($info['required']) {
                $required[] = $name;
            }
        }

        return $required;
    }

    /**
     * Get all parameter names
     *
     * @return string[]
     */
    public function getParameterNames(): array
    {
        return array_keys($this->parameters);
    }

    /**
     * Check if endpoint has parameters to test
     */
    public function hasParameters(): bool
    {
        return $this->parameters !== [];
    }

    /**
     * Get string representation for logging
     */
    public function __toString(): string
    {
        $params = [];
        foreach ($this->parameters as $name => $info) {
            $type = $info['type'];
            if (! $info['required']) {
                $type = '?' . $type;
            }

            $params[] = $type . ' $' . $name;
        }

        $paramStr = $params !== [] ? '(' . implode(', ', $params) . ')' : '';

        return sprintf('%s %s%s', $this->method, $this->uri, $paramStr);
    }
}
