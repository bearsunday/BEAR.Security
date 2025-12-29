<?php

declare(strict_types=1);

namespace BEAR\Security\Dast\Payload;

use BEAR\Security\VulnerabilityInterface;

use function str_repeat;

/**
 * CSRF (Cross-Site Request Forgery) detection payloads
 */
final class CsrfPayload implements PayloadInterface
{
    public function getType(): string
    {
        return 'CSRF';
    }

    public function getName(): string
    {
        return 'Cross-Site Request Forgery (CSRF)';
    }

    /** @return string[] */
    public function getPayloads(): array
    {
        return [
            // Empty/missing token
            '',
            'invalid_token',
            'null',
            '0',

            // Malformed tokens
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            '../../../etc/passwd',
            '<script>alert(1)</script>',

            // Token manipulation
            '%00',
            '%0a%0d',
            'undefined',
            'NaN',
            '[]',
            '{}',

            // Length attacks
            str_repeat('A', 1000),
            str_repeat('A', 10000),
        ];
    }

    /** @return string[] */
    public function getSuccessPatterns(): array
    {
        return [
            // JSON success responses (more specific patterns to avoid false positives)
            '/"success"\s*:\s*true/i',
            '/"status"\s*:\s*"ok"/i',
            '/"status"\s*:\s*"success"/i',
            '/"error"\s*:\s*false/i',
            '/"result"\s*:\s*"ok"/i',

            // Specific action confirmations with context
            '/record\s+(has\s+been\s+)?(updated|deleted|created|saved)/i',
            '/successfully\s+(updated|deleted|created|saved|submitted)/i',
            '/operation\s+completed/i',
            '/changes\s+saved/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_HIGH;
    }

    public function getDescription(): string
    {
        return 'CSRF vulnerability detected - state-changing action accepted without valid CSRF token';
    }

    public function getRecommendation(): string
    {
        return 'Implement CSRF token validation for all state-changing requests. Use SameSite cookie attribute. Verify Origin/Referer headers.';
    }
}
