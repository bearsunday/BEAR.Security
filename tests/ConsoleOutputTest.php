<?php

declare(strict_types=1);

namespace BEAR\Security;

use BEAR\Security\Output\ConsoleOutput;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function sprintf;

#[CoversClass(ConsoleOutput::class)]
class ConsoleOutputTest extends TestCase
{
    private const DOCS_URL = 'https://bearsunday.github.io/BEAR.Security/issues/en/';

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function typeToSlugProvider(): array
    {
        return [
            'SQL injection direct variable' => ['SQL_INJECTION_DIRECT_VARIABLE', 'sql-injection'],
            'SQL injection string concat' => ['SQL_INJECTION_STRING_CONCAT', 'sql-injection'],
            'XSS direct output' => ['XSS_DIRECT_OUTPUT', 'xss'],
            'XSS echo variable unsafe' => ['XSS_ECHO_VARIABLE_UNSAFE', 'xss'],
            'CSRF form no token' => ['CSRF_FORM_NO_TOKEN', 'csrf'],
            'Command injection exec' => ['COMMAND_INJECTION_EXEC', 'command-injection'],
            'Path traversal file' => ['PATH_TRAVERSAL_FILE', 'path-traversal'],
            'Remote file inclusion' => ['REMOTE_FILE_INCLUSION_INCLUDE', 'remote-file-inclusion'],
            'Cryptographic failures' => ['CRYPTOGRAPHIC_FAILURES_WEAK_HASH', 'cryptographic-failures'],
            'Dangerous function eval' => ['DANGEROUS_FUNCTION_EVAL', 'dangerous-function'],
            'Header injection' => ['HEADER_INJECTION_SET_COOKIE', 'header-injection'],
            'Insecure deserialization' => ['INSECURE_DESERIALIZATION_UNSERIALIZE', 'insecure-deserialization'],
            'Open redirect' => ['OPEN_REDIRECT_HEADER', 'open-redirect'],
            'Session security' => ['SESSION_SECURITY_FIXATION', 'session-security'],
            'Weak random' => ['WEAK_RANDOM_RAND', 'weak-random'],
            'XXE' => ['XXE_LOAD_XML', 'xxe'],
        ];
    }

    #[DataProvider('typeToSlugProvider')]
    public function testTypeToSlugConvertsToCorrectDocumentSlug(string $type, string $expectedSlug): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            $type,
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/test.php',
            10,
            'Test description',
            'test code',
            'Test recommendation',
        ));

        $output = new ConsoleOutput(false); // Disable colors for testing
        $formatted = $output->format($result);

        $expectedUrl = self::DOCS_URL . $expectedSlug;
        $this->assertStringContainsString(
            sprintf('see %s', $expectedUrl),
            $formatted,
            sprintf('Expected URL slug "%s" for type "%s"', $expectedSlug, $type),
        );
    }

    public function testFormatWithNoVulnerabilities(): void
    {
        $result = new ScanResult();
        $output = new ConsoleOutput(false);

        $formatted = $output->format($result);

        $this->assertStringContainsString('No security issues found!', $formatted);
    }

    public function testFormatWithVulnerabilitiesShowsSummary(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'SQL_INJECTION_DIRECT_VARIABLE',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/test.php',
            10,
            'SQL Injection detected',
            'test code',
            'Use prepared statements',
        ));
        $result->addVulnerability(new Vulnerability(
            'XSS_DIRECT_OUTPUT',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/view.php',
            20,
            'XSS detected',
            'echo code',
            'Escape output',
        ));

        $output = new ConsoleOutput(false);
        $formatted = $output->format($result);

        $this->assertStringContainsString('2 issues found:', $formatted);
        $this->assertStringContainsString('1 critical', $formatted);
        $this->assertStringContainsString('1 high', $formatted);
    }
}
