<?php

declare(strict_types=1);

namespace BEAR\Security\Dast;

use BEAR\AppMeta\AbstractAppMeta;
use BEAR\Resource\ResourceInterface;

use function array_keys;
use function in_array;
use function is_array;
use function json_decode;
use function preg_match;
use function strtoupper;

/**
 * Discovers all endpoints and their parameters from a BEAR.Sunday application
 */
final class EndpointDiscovery
{
    private const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

    public function __construct(
        private readonly AbstractAppMeta $meta,
        private readonly ResourceInterface $resource,
    ) {
    }

    /**
     * Discover all endpoints with their parameters
     *
     * @return Endpoint[]
     */
    public function discover(): array
    {
        $endpoints = [];

        /** @psalm-suppress MixedAssignment */
        foreach ($this->meta->getGenerator('*') as $resMeta) {
            /** @var object{uriPath: string} $resMeta */
            $fullUri = $resMeta->uriPath;

            // Parse and convert URI
            $parsed = $this->parseResourceUri($fullUri);
            if ($parsed === null) {
                continue;
            }

            [$httpPath, $bearUri] = $parsed;

            $methodParams = $this->getMethodParameters($bearUri);

            foreach ($methodParams as $method => $params) {
                if (! in_array($method, self::HTTP_METHODS, true)) {
                    continue;
                }

                $endpoints[] = new Endpoint($httpPath, $method, $params);
            }
        }

        return $endpoints;
    }

    /**
     * Parse resource URI and return HTTP path and BEAR resource URI
     *
     * Converts "resource://self/app/users" to ["/users", "app://self/users"]
     * Converts "resource://self/page/index" to ["/", "page://self/index"]
     *
     * @return array{0: string, 1: string}|null [HTTP path, BEAR resource URI] or null if not HTTP-accessible
     */
    private function parseResourceUri(string $resourceUri): array|null
    {
        // Match resource://self/app/... or resource://self/page/...
        if (! preg_match('#^resource://self/(app|page)/(.*)$#', $resourceUri, $matches)) {
            return null;
        }

        $scheme = $matches[1]; // 'app' or 'page'
        $path = $matches[2];   // 'safe/sql-injection' etc.

        // Build BEAR resource URI: app://self/safe/sql-injection
        $bearUri = $scheme . '://self/' . $path;

        // Build HTTP path: /safe/sql-injection
        $httpPath = '/' . $path;

        // /index becomes /
        if ($httpPath === '/index') {
            $httpPath = '/';
        }

        return [$httpPath, $bearUri];
    }

    /**
     * Get parameter information for all HTTP methods of a resource
     *
     * @return array<string, array<string, array{type: string, required: bool, default?: mixed}>>
     */
    private function getMethodParameters(string $uri): array
    {
        try {
            $ro = $this->resource->options($uri);

            // OPTIONS response is JSON in the view property
            $view = $ro->view;
            if (! is_string($view) || $view === '') {
                return [];
            }

            /** @var array<string, mixed>|null $data */
            $data = json_decode($view, true);
            if (! is_array($data)) {
                return [];
            }

            $result = [];
            foreach ($data as $method => $info) {
                $method = strtoupper((string) $method);
                if (! in_array($method, self::HTTP_METHODS, true)) {
                    continue;
                }

                $result[$method] = $this->parseParameters($info);
            }

            return $result;
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Parse parameter information from OPTIONS response
     *
     * OPTIONS response format:
     * {
     *   "GET": {
     *     "request": {
     *       "parameters": {"name": {"type": "string"}},
     *       "required": ["name"]
     *     }
     *   }
     * }
     *
     * @param mixed $info
     *
     * @return array<string, array{type: string, required: bool, default?: mixed}>
     */
    private function parseParameters(mixed $info): array
    {
        if (! is_array($info)) {
            return [];
        }

        // Navigate to request.parameters and request.required
        $request = $info['request'] ?? $info;
        if (! is_array($request)) {
            return [];
        }

        $parameters = $request['parameters'] ?? [];
        $required = $request['required'] ?? [];

        if (! is_array($parameters)) {
            return [];
        }

        if (! is_array($required)) {
            $required = [];
        }

        $result = [];
        foreach ($parameters as $name => $paramInfo) {
            $name = (string) $name;
            $type = is_array($paramInfo) ? ($paramInfo['type'] ?? 'string') : 'string';
            $isRequired = in_array($name, $required, true);

            $param = [
                'type' => (string) $type,
                'required' => $isRequired,
            ];

            if (is_array($paramInfo) && isset($paramInfo['default'])) {
                $param['default'] = $paramInfo['default'];
            }

            $result[$name] = $param;
        }

        return $result;
    }
}
