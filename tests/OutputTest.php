<?php

declare(strict_types=1);

namespace BEAR\Security;

use BEAR\Security\Output\SarifOutput;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function array_column;
use function assert;
use function is_array;
use function json_decode;

#[CoversClass(SarifOutput::class)]
#[CoversClass(ScanResult::class)]
#[CoversClass(Vulnerability::class)]
class OutputTest extends TestCase
{
    /** @return array<array-key, mixed> */
    private function decodeJson(string $json): array
    {
        $data = json_decode($json, true);
        assert(is_array($data));

        return $data;
    }

    public function testSarifOutputFormat(): void
    {
        $result = new ScanResult();
        $output = new SarifOutput();

        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $this->assertSame('2.1.0', $data['version']);
        $this->assertArrayHasKey('$schema', $data);
        $this->assertArrayHasKey('runs', $data);
    }

    public function testSarifOutputWithVulnerabilities(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'SQL_INJECTION_GET',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/src/test.php',
            10,
            'SQL Injection detected',
            '$query = "SELECT * FROM users WHERE id=" . $_GET["id"]',
            'Use prepared statements',
        ));
        $result->addVulnerability(new Vulnerability(
            'XSS_DIRECT_OUTPUT',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/view.php',
            25,
            'XSS vulnerability',
            'echo $_GET["name"]',
            'Escape output',
        ));

        $output = new SarifOutput();
        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $results = $runs[0]['results'];
        assert(is_array($results));
        $this->assertCount(2, $results);
    }

    public function testSarifOutputToolInfo(): void
    {
        $result = new ScanResult();
        $output = new SarifOutput();

        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $tool = $runs[0]['tool'];
        assert(is_array($tool) && is_array($tool['driver']));
        $this->assertSame('BEAR.SecurityScanner', $tool['driver']['name']);
        $this->assertArrayHasKey('rules', $tool['driver']);
    }

    public function testSarifOutputRules(): void
    {
        $result = new ScanResult();
        $output = new SarifOutput();

        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $tool = $runs[0]['tool'];
        assert(is_array($tool) && is_array($tool['driver']));
        $rules = $tool['driver']['rules'];
        assert(is_array($rules));
        $this->assertNotEmpty($rules);

        // Check that rules have expected structure
        $ruleIds = array_column($rules, 'id');
        $this->assertContains('SQL_INJECTION', $ruleIds);
        $this->assertContains('XSS', $ruleIds);
    }

    public function testSarifOutputSeverityMapping(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'CRITICAL_ISSUE',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/test.php',
            1,
            'Critical issue',
            'code',
            'fix',
        ));
        $result->addVulnerability(new Vulnerability(
            'HIGH_ISSUE',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/test.php',
            2,
            'High issue',
            'code',
            'fix',
        ));
        $result->addVulnerability(new Vulnerability(
            'MEDIUM_ISSUE',
            VulnerabilityInterface::SEVERITY_MEDIUM,
            '/app/test.php',
            3,
            'Medium issue',
            'code',
            'fix',
        ));
        $result->addVulnerability(new Vulnerability(
            'LOW_ISSUE',
            VulnerabilityInterface::SEVERITY_LOW,
            '/app/test.php',
            4,
            'Low issue',
            'code',
            'fix',
        ));

        $output = new SarifOutput();
        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $results = $runs[0]['results'];
        assert(is_array($results));

        assert(isset($results[0]) && is_array($results[0]));
        assert(isset($results[1]) && is_array($results[1]));
        assert(isset($results[2]) && is_array($results[2]));
        assert(isset($results[3]) && is_array($results[3]));

        $this->assertSame('error', $results[0]['level']); // critical
        $this->assertSame('error', $results[1]['level']); // high
        $this->assertSame('warning', $results[2]['level']); // medium
        $this->assertSame('note', $results[3]['level']); // low
    }

    public function testSarifOutputInvocations(): void
    {
        $result = new ScanResult();
        $output = new SarifOutput();

        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $invocations = $runs[0]['invocations'];
        assert(is_array($invocations) && isset($invocations[0]) && is_array($invocations[0]));
        $this->assertCount(1, $invocations);
        $this->assertTrue($invocations[0]['executionSuccessful']);
        $this->assertArrayHasKey('endTimeUtc', $invocations[0]);
    }

    public function testSarifOutputLocationInfo(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'TEST_ISSUE',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/Controller.php',
            42,
            'Test issue',
            'vulnerable code',
            'Fix recommendation',
        ));

        $output = new SarifOutput();
        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $results = $runs[0]['results'];
        assert(is_array($results) && isset($results[0]) && is_array($results[0]));
        $locations = $results[0]['locations'];
        assert(is_array($locations) && isset($locations[0]) && is_array($locations[0]));
        $location = $locations[0]['physicalLocation'];
        assert(is_array($location) && is_array($location['artifactLocation']) && is_array($location['region']));

        $this->assertSame('/app/src/Controller.php', $location['artifactLocation']['uri']);
        $this->assertSame(42, $location['region']['startLine']);
    }

    public function testSarifOutputFixes(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'TEST_ISSUE',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/test.php',
            10,
            'Test issue',
            'vulnerable code',
            'Use prepared statements instead',
        ));

        $output = new SarifOutput();
        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $results = $runs[0]['results'];
        assert(is_array($results) && isset($results[0]) && is_array($results[0]));
        $fixes = $results[0]['fixes'];
        assert(is_array($fixes) && isset($fixes[0]) && is_array($fixes[0]));
        $description = $fixes[0]['description'];
        assert(is_array($description));

        $this->assertCount(1, $fixes);
        $this->assertSame('Use prepared statements instead', $description['text']);
    }

    public function testSarifOutputZeroLine(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'TEST_ISSUE',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/test.php',
            0, // Zero line
            'Test issue',
            'code',
            'fix',
        ));

        $output = new SarifOutput();
        $sarif = $output->format($result);
        $data = $this->decodeJson($sarif);

        $runs = $data['runs'];
        assert(is_array($runs) && isset($runs[0]) && is_array($runs[0]));
        $results = $runs[0]['results'];
        assert(is_array($results) && isset($results[0]) && is_array($results[0]));
        $locations = $results[0]['locations'];
        assert(is_array($locations) && isset($locations[0]) && is_array($locations[0]));
        $physicalLocation = $locations[0]['physicalLocation'];
        assert(is_array($physicalLocation) && is_array($physicalLocation['region']));

        // Line 0 should be converted to 1
        $startLine = $physicalLocation['region']['startLine'];
        $this->assertSame(1, $startLine);
    }
}
