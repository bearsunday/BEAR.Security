<?php

declare(strict_types=1);

namespace BEAR\Security\Dast;

use BEAR\Resource\ResourceInterface;
use BEAR\Security\Dast\Analyzer\ResponseAnalyzer;
use BEAR\Security\Dast\Payload\CommandInjectionPayload;
use BEAR\Security\Dast\Payload\CsrfPayload;
use BEAR\Security\Dast\Payload\PathTraversalPayload;
use BEAR\Security\Dast\Payload\PayloadInterface;
use BEAR\Security\Dast\Payload\RemoteFileInclusionPayload;
use BEAR\Security\Dast\Payload\SqlInjectionPayload;
use BEAR\Security\Dast\Payload\XssPayload;
use BEAR\Security\ScanResult;
use BEAR\Security\VulnerabilityInterface;
use Throwable;

use function array_merge;
use function count;
use function microtime;
use function sprintf;
use function strtolower;

/**
 * Automatic DAST Scanner for BEAR.Sunday applications
 *
 * Discovers all endpoints automatically and runs security tests
 */
final class AutoDastScanner
{
    /** @var PayloadInterface[] */
    private array $payloads;
    private ResponseAnalyzer $analyzer;

    /** @var callable(Endpoint, string): void|null */
    private $progressCallback = null;

    /**
     * @param PayloadInterface[]|null $payloads Custom payloads or null for defaults
     */
    public function __construct(
        private readonly EndpointDiscovery $discovery,
        private readonly ResourceInterface $resource,
        array|null $payloads = null,
    ) {
        $this->payloads = $payloads ?? $this->getDefaultPayloads();
        $this->analyzer = new ResponseAnalyzer();
    }

    /** @return PayloadInterface[] */
    private function getDefaultPayloads(): array
    {
        return [
            new SqlInjectionPayload(),
            new XssPayload(),
            new CommandInjectionPayload(),
            new PathTraversalPayload(),
            new RemoteFileInclusionPayload(),
            new CsrfPayload(),
        ];
    }

    /**
     * Set progress callback for reporting scan progress
     *
     * @param callable(Endpoint, string): void $callback
     */
    public function setProgressCallback(callable $callback): self
    {
        $this->progressCallback = $callback;

        return $this;
    }

    /**
     * Discover all endpoints in the application
     *
     * @return Endpoint[]
     */
    public function discoverEndpoints(): array
    {
        return $this->discovery->discover();
    }

    /**
     * Scan all discovered endpoints
     */
    public function scan(): ScanResult
    {
        $startTime = microtime(true);
        $result = new ScanResult();

        $endpoints = $this->discovery->discover();

        foreach ($endpoints as $endpoint) {
            $this->reportProgress($endpoint, 'scanning');

            $vulnerabilities = $this->scanEndpoint($endpoint);
            $result->addVulnerabilities($vulnerabilities);
            $result->incrementFilesScanned();

            $status = $vulnerabilities === [] ? 'ok' : sprintf('%d issues', count($vulnerabilities));
            $this->reportProgress($endpoint, $status);
        }

        $result->setScanTime(microtime(true) - $startTime);

        return $result;
    }

    /**
     * Scan a single endpoint
     *
     * @return VulnerabilityInterface[]
     */
    public function scanEndpoint(Endpoint $endpoint): array
    {
        $vulnerabilities = [];

        if (! $endpoint->hasParameters()) {
            return [];
        }

        foreach ($endpoint->getParameterNames() as $paramName) {
            foreach ($this->payloads as $payloadType) {
                $found = $this->testPayloads($endpoint, $paramName, $payloadType);
                $vulnerabilities = array_merge($vulnerabilities, $found);
            }
        }

        return $vulnerabilities;
    }

    /**
     * Test payloads against a specific parameter
     *
     * @return VulnerabilityInterface[]
     */
    private function testPayloads(
        Endpoint $endpoint,
        string $paramName,
        PayloadInterface $payloadType,
    ): array {
        $vulnerabilities = [];
        $method = strtolower($endpoint->method);

        foreach ($payloadType->getPayloads() as $payload) {
            // Build query with payload injected into the target parameter
            $query = $this->buildQueryWithPayload($endpoint, $paramName, $payload);

            try {
                // Make request using ResourceInterface
                $ro = $this->resource->{$method}($endpoint->uri, $query);

                $body = (string) $ro;
                $code = $ro->code;

                $vulnerability = $this->analyzer->analyze(
                    $payloadType,
                    $body,
                    $code,
                    sprintf('%s %s?%s=%s', $endpoint->method, $endpoint->uri, $paramName, $payload),
                    $payload,
                );

                if ($vulnerability !== null) {
                    $vulnerabilities[] = $vulnerability;
                }
            } catch (Throwable) {
                // Request failed, continue with next payload
            }
        }

        return $vulnerabilities;
    }

    /**
     * Build query array with payload injected into specific parameter
     *
     * @return array<string, string|int|float|bool>
     */
    private function buildQueryWithPayload(Endpoint $endpoint, string $targetParam, string $payload): array
    {
        /** @var array<string, string|int|float|bool> $query */
        $query = [];

        foreach ($endpoint->parameters as $name => $info) {
            if ($name === $targetParam) {
                $query[$name] = $payload;
            } elseif ($info['required']) {
                // Use default value or generate a safe test value
                $default = $info['default'] ?? null;
                $query[$name] = $default !== null ? (string) $default : $this->getSafeTestValue($info['type']);
            }
        }

        return $query;
    }

    /**
     * Get a safe test value for a parameter type
     */
    private function getSafeTestValue(string $type): string|int|float|bool
    {
        return match ($type) {
            'int', 'integer' => 1,
            'float', 'double' => 1.0,
            'bool', 'boolean' => true,
            default => 'test',
        };
    }

    /**
     * Report progress via callback
     */
    private function reportProgress(Endpoint $endpoint, string $status): void
    {
        if ($this->progressCallback !== null) {
            ($this->progressCallback)($endpoint, $status);
        }
    }
}
