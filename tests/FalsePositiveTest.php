<?php

declare(strict_types=1);

namespace BEAR\Security;

use BEAR\Security\Detector\CommandInjectionDetector;
use BEAR\Security\Detector\CryptographicFailuresDetector;
use BEAR\Security\Detector\DangerousFunctionDetector;
use PHPUnit\Framework\TestCase;

/**
 * Tests for false positive reduction in detectors
 */
class FalsePositiveTest extends TestCase
{
    // =========================================================================
    // DangerousFunctionDetector - DANGEROUS_EXEC
    // =========================================================================

    public function testPdoExecIsNotDetectedAsShellExec(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = '<?php $pdo->exec("UPDATE users SET active = 1");';

        $vulnerabilities = $detector->scan('test.php', $code);

        $execVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'DANGEROUS_EXEC'),
        );

        $this->assertEmpty($execVulns, 'PDO::exec() should not be detected as shell exec');
    }

    public function testShellExecIsStillDetected(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = '<?php shell_exec("ls -la");';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('DANGEROUS_EXEC', $vulnerabilities[0]->getType());
    }

    public function testExecFunctionIsStillDetected(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = '<?php exec("whoami");';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('DANGEROUS_EXEC', $vulnerabilities[0]->getType());
    }

    // =========================================================================
    // DangerousFunctionDetector - DANGEROUS_UNSERIALIZE
    // =========================================================================

    public function testUnserializeWithAllowedClassesFalseIsNotDetected(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = '<?php $data = unserialize($input, ["allowed_classes" => false]);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $unserializeVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'UNSERIALIZE'),
        );

        $this->assertEmpty($unserializeVulns, 'unserialize with allowed_classes should not be flagged');
    }

    public function testUnserializeWithoutOptionsIsDetected(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = '<?php $data = unserialize($input);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
    }

    // =========================================================================
    // CryptographicFailuresDetector - WEAK_HASH_MD5
    // =========================================================================

    public function testMd5ForCacheKeyIsNotDetected(): void
    {
        $detector = new CryptographicFailuresDetector();
        $code = '<?php $cacheKey = md5($content);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $md5Vulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'WEAK_HASH_MD5'),
        );

        $this->assertEmpty($md5Vulns, 'md5 for cache/content should not be flagged');
    }

    public function testMd5ForPasswordIsDetected(): void
    {
        $detector = new CryptographicFailuresDetector();
        $code = '<?php $hash = md5($password);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('MD5', $vulnerabilities[0]->getType());
    }

    // =========================================================================
    // CryptographicFailuresDetector - HARDCODED_DB_PASSWORD
    // =========================================================================

    public function testPlaceholderPasswordIsNotDetected(): void
    {
        $detector = new CryptographicFailuresDetector();
        $code = '<?php $config = ["password" => "YOUR_PASSWORD_HERE"];';

        $vulnerabilities = $detector->scan('test.php', $code);

        $pwVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'HARDCODED_DB_PASSWORD'),
        );

        $this->assertEmpty($pwVulns, 'Placeholder passwords should not be flagged');
    }

    public function testRealHardcodedPasswordIsDetected(): void
    {
        $detector = new CryptographicFailuresDetector();
        $code = '<?php $config = ["password" => "supersecret123"];';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
    }

    // =========================================================================
    // CommandInjectionDetector - COMMAND_INJECTION_VARIABLE
    // =========================================================================

    public function testSafeVariableIsNotDetected(): void
    {
        $detector = new CommandInjectionDetector();
        $code = '<?php $safe = escapeshellarg($input); shell_exec($safe);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $cmdVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'COMMAND_INJECTION_VARIABLE'),
        );

        $this->assertEmpty($cmdVulns, '$safe variable should not be flagged');
    }

    public function testEscapedVariableIsNotDetected(): void
    {
        $detector = new CommandInjectionDetector();
        $code = '<?php $escaped = escapeshellcmd($cmd); exec($escaped);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $cmdVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'COMMAND_INJECTION_VARIABLE'),
        );

        $this->assertEmpty($cmdVulns, '$escaped variable should not be flagged');
    }

    public function testUnsafeVariableIsStillDetected(): void
    {
        $detector = new CommandInjectionDetector();
        $code = '<?php $userInput = $_GET["cmd"]; exec($userInput);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
    }

    // =========================================================================
    // @security-ignore comment suppression
    // =========================================================================

    public function testSecurityIgnoreAllTypes(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = <<<'PHP'
<?php
// @security-ignore
shell_exec("ls -la");
PHP;

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertEmpty($vulnerabilities, '@security-ignore should suppress all types');
    }

    public function testSecurityIgnoreSpecificType(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = <<<'PHP'
<?php
// @security-ignore DANGEROUS_EXEC
shell_exec("ls -la");
PHP;

        $vulnerabilities = $detector->scan('test.php', $code);

        $execVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'DANGEROUS_EXEC'),
        );

        $this->assertEmpty($execVulns, '@security-ignore TYPE should suppress specific type');
    }

    public function testSecurityIgnoreWithReason(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = <<<'PHP'
<?php
// @security-ignore DANGEROUS_EXEC: This is a safe static command
shell_exec("date +%Y-%m-%d");
PHP;

        $vulnerabilities = $detector->scan('test.php', $code);

        $execVulns = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => str_contains($v->getType(), 'DANGEROUS_EXEC'),
        );

        $this->assertEmpty($execVulns, '@security-ignore TYPE: reason should work');
    }

    public function testSecurityIgnoreWrongTypeStillDetected(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = <<<'PHP'
<?php
// @security-ignore SQL_INJECTION
shell_exec("ls -la");
PHP;

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities, 'Wrong type should not suppress');
    }

    public function testSecurityIgnoreOnSameLine(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = <<<'PHP'
<?php
shell_exec("ls -la"); // @security-ignore
PHP;

        $vulnerabilities = $detector->scan('test.php', $code);

        // Same-line inline comment IS supported
        $this->assertEmpty($vulnerabilities, '@security-ignore on same line should work');
    }

    public function testNoIgnoreCommentStillDetected(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = <<<'PHP'
<?php
// This is a regular comment
shell_exec("ls -la");
PHP;

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities, 'Regular comment should not suppress');
    }
}
