<?php

declare(strict_types=1);

namespace BEAR\Security;

use BEAR\Security\Report\SecurityChecklistReport;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

use function array_keys;
use function is_array;
use function json_decode;
use function sprintf;

class SecurityChecklistReportTest extends TestCase
{
    public function testGenerateTextReportWithNoVulnerabilities(): void
    {
        $result = new ScanResult();
        $report = new SecurityChecklistReport();

        $output = $report->generate($result, 'text');

        $this->assertStringContainsString('OWASP Top 10 Security Report', $output);
        $this->assertStringContainsString('[✓] PASS A01', $output);
        $this->assertStringContainsString('[✓] PASS A02', $output);
        $this->assertStringContainsString('[✓] PASS A03', $output);
        $this->assertStringContainsString('[✓] PASS A04', $output);
    }

    public function testGenerateTextReportWithVulnerabilities(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'SQL_INJECTION',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/src/test.php',
            10,
            'SQL Injection detected',
            '$query = "SELECT * FROM users WHERE id=" . $_GET["id"]',
            'Use prepared statements',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'text');

        $this->assertStringContainsString('[✗] FAIL A03', $output);
        $this->assertStringContainsString('SQL_INJECTION', $output);
    }

    public function testGenerateJsonReport(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'XSS',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/test.php',
            20,
            'XSS detected',
            'echo $_GET["name"]',
            'Escape output',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $this->assertSame('OWASP Top 10 Security Checklist', $data['report']);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('checklist', $data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A03']['status']);
    }

    public function testGenerateHtmlReport(): void
    {
        $result = new ScanResult();
        $report = new SecurityChecklistReport();

        $output = $report->generate($result, 'html');

        $this->assertStringContainsString('<!DOCTYPE html>', $output);
        $this->assertStringContainsString('OWASP Top 10 Security Report', $output);
        $this->assertStringContainsString('class="check-item', $output);
    }

    public function testPathTraversalMapsToA01(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'PATH_TRAVERSAL',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/file.php',
            15,
            'Path traversal detected',
            'include($_GET["page"])',
            'Validate file paths',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A01']['status']);
    }

    public function testCsrfMapsToA07(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'CSRF_FORM_NO_TOKEN',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/form.php',
            25,
            'CSRF token missing',
            '<form method="post">',
            'Add CSRF token',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A07']['status']);
    }

    public function testSsrfMapsToA10(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'RFI_FILE_GET_CONTENTS_URL',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/src/api.php',
            30,
            'SSRF detected',
            'file_get_contents($_GET["url"])',
            'Validate URLs',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A10']['status']);
    }

    public function testSummaryCalculation(): void
    {
        $result = new ScanResult();
        $report = new SecurityChecklistReport();

        $output = $report->generate($result, 'json');
        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $summary = $data['summary'];
        $this->assertIsArray($summary);

        // All 10 PASS by default (BEAR.Sunday framework provides secure design)
        $this->assertSame(10, $summary['total']);
        $this->assertSame(10, $summary['passed']);
        $this->assertSame(0, $summary['failed']);
        $this->assertEquals(100, $summary['score']);
    }

    public function testXxeMapsToA05(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'XXE_SIMPLEXML_USER_INPUT',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/src/file.php',
            10,
            'XXE detected',
            'simplexml_load_string($_GET["xml"])',
            'Disable external entity loading',
        ));

        $report = new SecurityChecklistReport();
        $data = json_decode($report->generate($result, 'json'), true);
        $this->assertIsArray($data);
        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A05']['status']);
    }

    public function testOpenRedirectMapsToA01(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'OPEN_REDIRECT_HEADER',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/file.php',
            12,
            'Open redirect detected',
            'header("Location: " . $_GET["url"])',
            'Validate redirect targets',
        ));

        $report = new SecurityChecklistReport();
        $data = json_decode($report->generate($result, 'json'), true);
        $this->assertIsArray($data);
        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A01']['status']);
    }

    public function testHeaderInjectionMapsToA05(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'HEADER_INJECTION_USER_INPUT',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/file.php',
            8,
            'Header injection detected',
            'header("X-Foo: " . $_GET["h"])',
            'Sanitize header values',
        ));

        $report = new SecurityChecklistReport();
        $data = json_decode($report->generate($result, 'json'), true);
        $this->assertIsArray($data);
        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A05']['status']);
    }

    public function testWeakRandomMapsToA02(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'WEAK_RANDOM_RAND',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/file.php',
            5,
            'Weak random token',
            '$token = rand();',
            'Use random_int() for security-sensitive values',
        ));

        $report = new SecurityChecklistReport();
        $data = json_decode($report->generate($result, 'json'), true);
        $this->assertIsArray($data);
        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A02']['status']);
    }

    public function testDangerousUnserializeMapsToA08NotA03(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'DANGEROUS_UNSERIALIZE',
            VulnerabilityInterface::SEVERITY_MEDIUM,
            '/app/src/file.php',
            20,
            'unserialize() without allowed_classes option',
            'unserialize($data);',
            'Use allowed_classes option or JSON instead',
        ));

        $report = new SecurityChecklistReport();
        $data = json_decode($report->generate($result, 'json'), true);
        $this->assertIsArray($data);
        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A08']['status'], 'CWE-502 deserialization must file under A08, not A03 Injection');
        $this->assertSame('PASS', $checklist['A03']['status']);
    }

    /**
     * Regression guard: every type a default detector can emit must map to at least one
     * OWASP category, or it silently disappears from the checklist/compliance score.
     */
    public function testEveryDefaultDetectorTypeIsCategorized(): void
    {
        $scanner = new Scanner();

        foreach ($scanner->getDetectors() as $detector) {
            $property = new ReflectionProperty($detector, 'patterns');
            $property->setAccessible(true);
            /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> $patterns */
            $patterns = $property->getValue($detector);

            foreach (array_keys($patterns) as $type) {
                $result = new ScanResult();
                $result->addVulnerability(new Vulnerability(
                    $type,
                    VulnerabilityInterface::SEVERITY_HIGH,
                    '/app/src/file.php',
                    1,
                    'test',
                    'test',
                    'test',
                ));

                $data = json_decode((new SecurityChecklistReport())->generate($result, 'json'), true);
                $this->assertIsArray($data);
                $checklist = $data['checklist'];
                $this->assertIsArray($checklist);

                $hasFailure = false;
                foreach ($checklist as $item) {
                    if (is_array($item) && ($item['status'] ?? null) === 'FAIL') {
                        $hasFailure = true;
                        break;
                    }
                }

                $this->assertTrue($hasFailure, sprintf(
                    'Detector type "%s" (%s) is not mapped to any OWASP category and silently vanishes from the checklist.',
                    $type,
                    $detector->getName(),
                ));
            }
        }
    }
}
