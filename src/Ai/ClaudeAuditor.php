<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use BEAR\Security\Vulnerability;
use RuntimeException;

use function array_map;
use function curl_close;
use function curl_error;
use function curl_exec;
use function curl_getinfo;
use function curl_init;
use function curl_setopt;
use function getenv;
use function is_string;
use function json_decode;
use function json_encode;

use const CURLINFO_HTTP_CODE;
use const CURLOPT_CONNECTTIMEOUT;
use const CURLOPT_HTTPHEADER;
use const CURLOPT_POST;
use const CURLOPT_POSTFIELDS;
use const CURLOPT_RETURNTRANSFER;
use const CURLOPT_TIMEOUT;
use const CURLOPT_URL;
use const JSON_THROW_ON_ERROR;

/**
 * Claude-based security auditor
 *
 * Supports two authentication methods:
 * 1. API key (ANTHROPIC_API_KEY) - Direct API calls
 * 2. Claude CLI (Max plan) - Uses authenticated claude CLI
 */
final class ClaudeAuditor implements AuditorInterface
{
    private const API_URL = 'https://api.anthropic.com/v1/messages';
    private const MODEL = 'claude-sonnet-4-20250514';
    private const MAX_TOKENS = 8192;

    private const MODE_API = 'api';
    private const MODE_CLI = 'cli';

    private string $mode;
    private ?string $apiKey = null;
    private ?ClaudeCliAdapter $cliAdapter = null;
    private PromptBuilder $promptBuilder;
    private FileCollector $fileCollector;
    private TokenTracker $tokenTracker;

    public function __construct(?string $apiKey = null)
    {
        $key = $apiKey ?? getenv('ANTHROPIC_API_KEY');

        if (is_string($key) && $key !== '') {
            // API key available - use direct API
            $this->mode = self::MODE_API;
            $this->apiKey = $key;
        } elseif (ClaudeCliAdapter::isAvailable()) {
            // No API key but Claude CLI available - use CLI
            $this->mode = self::MODE_CLI;
            $this->cliAdapter = new ClaudeCliAdapter();
        } else {
            throw new RuntimeException(
                "No authentication method available.\n" .
                "Either set ANTHROPIC_API_KEY environment variable,\n" .
                "or install and authenticate Claude CLI (claude --version)"
            );
        }

        $this->promptBuilder = new PromptBuilder();
        $this->fileCollector = new FileCollector();
        $this->tokenTracker = new TokenTracker();
    }

    /**
     * Get the current authentication mode
     */
    public function getMode(): string
    {
        return $this->mode;
    }

    public function audit(string $projectPath): AuditResult
    {
        $files = $this->fileCollector->collect($projectPath);
        $prompt = $this->promptBuilder->build($files);

        $responseContent = $this->mode === self::MODE_API
            ? $this->callApi($prompt)
            : $this->callCli($prompt);

        $parsed = $this->promptBuilder->parseResponse($responseContent);

        $vulnerabilities = array_map(
            static fn (array $v) => new Vulnerability(
                $v['type'],
                $v['severity'],
                $v['file'],
                $v['line'],
                $v['description'],
                $v['code'] ?? '',
                '',
            ),
            $parsed['vulnerabilities'],
        );

        $filesAnalyzed = [];
        foreach ($files as $path => $content) {
            $filesAnalyzed[$path] = 'analyzed';
        }

        return new AuditResult(
            $vulnerabilities,
            $this->tokenTracker,
            $filesAnalyzed,
            [],
        );
    }

    /**
     * Call Claude API directly
     */
    private function callApi(string $prompt): string
    {
        if ($this->apiKey === null) {
            throw new RuntimeException('API key not set');
        }

        $payload = [
            'model' => self::MODEL,
            'max_tokens' => self::MAX_TOKENS,
            'messages' => [
                ['role' => 'user', 'content' => $prompt],
            ],
        ];

        $ch = curl_init();
        if ($ch === false) {
            throw new RuntimeException('Failed to initialize cURL');
        }

        curl_setopt($ch, CURLOPT_URL, self::API_URL);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_THROW_ON_ERROR));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'x-api-key: ' . $this->apiKey,
            'anthropic-version: 2023-06-01',
        ]);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_TIMEOUT, 300);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (! is_string($response) || $response === '') {
            throw new RuntimeException('API request failed: ' . ($error !== '' ? $error : 'empty response'));
        }

        if ($httpCode >= 400) {
            throw new RuntimeException("API request failed with HTTP {$httpCode}: {$response}");
        }

        /** @var array{content: array<array{text: string}>, usage: array{input_tokens: int, output_tokens: int}} $data */
        $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

        $inputTokens = $data['usage']['input_tokens'];
        $outputTokens = $data['usage']['output_tokens'];

        $this->tokenTracker->record('api_call', $inputTokens, $outputTokens);

        return $data['content'][0]['text'] ?? '';
    }

    /**
     * Call Claude CLI (for Max plan users)
     */
    private function callCli(string $prompt): string
    {
        if ($this->cliAdapter === null) {
            throw new RuntimeException('CLI adapter not initialized');
        }

        $response = $this->cliAdapter->send($prompt);

        // CLI doesn't provide token counts, estimate based on content length
        $estimatedInputTokens = (int) (mb_strlen($prompt) / 4);
        $estimatedOutputTokens = (int) (mb_strlen($response) / 4);

        $this->tokenTracker->record('cli_call', $estimatedInputTokens, $estimatedOutputTokens);

        return $response;
    }
}
