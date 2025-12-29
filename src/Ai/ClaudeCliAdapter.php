<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use RuntimeException;

use function escapeshellarg;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function is_string;
use function json_decode;
use function proc_close;
use function proc_open;
use function shell_exec;
use function stream_get_contents;
use function sys_get_temp_dir;
use function tempnam;
use function trim;
use function unlink;

use const JSON_THROW_ON_ERROR;

/**
 * Claude CLI adapter for Max plan users
 *
 * Uses the `claude` CLI tool instead of direct API calls,
 * allowing Max plan subscribers to use AI auditor without API key.
 */
final class ClaudeCliAdapter
{
    private string $claudePath;

    public function __construct(?string $claudePath = null)
    {
        $this->claudePath = $claudePath ?? $this->findClaudeCli();
    }

    /**
     * Check if Claude CLI is available and authenticated
     */
    public static function isAvailable(): bool
    {
        $output = shell_exec('which claude 2>/dev/null');

        if (! is_string($output) || trim($output) === '') {
            return false;
        }

        // Check if authenticated by running a simple command
        $checkOutput = shell_exec('claude --version 2>/dev/null');

        return is_string($checkOutput) && trim($checkOutput) !== '';
    }

    /**
     * Send prompt to Claude CLI and get response
     */
    public function send(string $prompt): string
    {
        // Write prompt to temp file to avoid shell escaping issues
        $tempFile = tempnam(sys_get_temp_dir(), 'claude_prompt_');
        if ($tempFile === false) {
            throw new RuntimeException('Failed to create temp file for prompt');
        }

        try {
            file_put_contents($tempFile, $prompt);

            $command = $this->claudePath . ' --print --dangerously-skip-permissions < ' . escapeshellarg($tempFile) . ' 2>&1';

            $descriptorspec = [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ];

            $process = proc_open($command, $descriptorspec, $pipes, null, null, ['bypass_shell' => false]);

            if (! is_resource($process)) {
                throw new RuntimeException('Failed to start Claude CLI process');
            }

            // Close stdin
            fclose($pipes[0]);

            // Read stdout
            $stdout = stream_get_contents($pipes[1]);
            fclose($pipes[1]);

            // Read stderr
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[2]);

            $exitCode = proc_close($process);

            if ($exitCode !== 0) {
                throw new RuntimeException('Claude CLI failed: ' . ($stderr ?: 'Unknown error'));
            }

            if (! is_string($stdout) || $stdout === '') {
                throw new RuntimeException('Empty response from Claude CLI');
            }

            return $stdout;
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    private function findClaudeCli(): string
    {
        $output = shell_exec('which claude 2>/dev/null');

        if (is_string($output) && trim($output) !== '') {
            return trim($output);
        }

        // Common installation paths
        $home = getenv('HOME');
        $paths = [
            '/usr/local/bin/claude',
            '/opt/homebrew/bin/claude',
        ];

        if (is_string($home) && $home !== '') {
            $paths[] = $home . '/.local/bin/claude';
        }

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        throw new RuntimeException(
            'Claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-code'
        );
    }
}
