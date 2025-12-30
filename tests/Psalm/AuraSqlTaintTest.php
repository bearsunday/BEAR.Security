<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Psalm;

use PHPUnit\Framework\TestCase;

use function exec;
use function implode;
use function preg_match_all;

/**
 * Integration test for Aura.Sql Psalm taint annotations
 *
 * Verifies that the stub file correctly enables SQL injection detection
 * for all ExtendedPdoInterface methods.
 */
class AuraSqlTaintTest extends TestCase
{
    private const PSALM_BIN = __DIR__ . '/../../vendor/bin/psalm';
    private const VULNERABLE_FILE = __DIR__ . '/../../demo/src/Resource/App/Vulnerable/AuraSqlInjection.php';
    private const VULNERABLE_EDGE_CASES = __DIR__ . '/../../demo/src/Resource/App/Vulnerable/AuraSqlEdgeCases.php';
    private const SAFE_FILE = __DIR__ . '/../../demo/src/Resource/App/Safe/AuraSqlPrepared.php';
    private const SAFE_EDGE_CASES = __DIR__ . '/../../demo/src/Resource/App/Safe/AuraSqlEdgeCases.php';

    /**
     * Test that vulnerable patterns are detected
     *
     * Expected detections:
     * - PdoInterface: query(), exec(), prepare()
     * - ExtendedPdoInterface: fetchAll(), fetchAffected(), fetchAssoc(), fetchCol(),
     *   fetchOne(), fetchPairs(), fetchValue(), perform(), prepareWithValues()
     * - Generators: yieldAll(), yieldAssoc(), yieldCol(), yieldPairs()
     */
    public function testVulnerablePatternsDetected(): void
    {
        $output = $this->runPsalmTaintAnalysis(self::VULNERABLE_FILE);
        $errorCount = $this->countTaintedSqlErrors($output);

        // Should detect TaintedSql for all vulnerable methods
        // Minimum expected: 16 (4 on* methods with multiple vulnerable calls)
        $this->assertGreaterThanOrEqual(16, $errorCount, sprintf(
            "Expected at least 16 TaintedSql errors, got %d.\nOutput:\n%s",
            $errorCount,
            $output
        ));
    }

    /**
     * Test that safe patterns are not flagged
     *
     * Safe patterns include:
     * - Using $values parameter for binding
     * - Using quote()/quoteName()/quoteSingleName() for escaping
     * - Using prepare() with bound parameters
     */
    public function testSafePatternsNotFlagged(): void
    {
        $output = $this->runPsalmTaintAnalysis(self::SAFE_FILE);
        $errorCount = $this->countTaintedSqlErrors($output);

        $this->assertSame(0, $errorCount, sprintf(
            "Expected 0 TaintedSql errors for safe patterns, got %d.\nOutput:\n%s",
            $errorCount,
            $output
        ));
    }

    /**
     * Test vulnerable edge cases (heredoc, interpolation, various methods)
     */
    public function testVulnerableEdgeCasesDetected(): void
    {
        $output = $this->runPsalmTaintAnalysis(self::VULNERABLE_EDGE_CASES);
        $errorCount = $this->countTaintedSqlErrors($output);

        // Should detect all 5 edge case patterns
        $this->assertSame(5, $errorCount, sprintf(
            "Expected 5 TaintedSql errors for edge cases, got %d.\nOutput:\n%s",
            $errorCount,
            $output
        ));
    }

    /**
     * Test safe edge cases (variable escaping, chaining, multiple bindings)
     */
    public function testSafeEdgeCasesNotFlagged(): void
    {
        $output = $this->runPsalmTaintAnalysis(self::SAFE_EDGE_CASES);
        $errorCount = $this->countTaintedSqlErrors($output);

        $this->assertSame(0, $errorCount, sprintf(
            "Expected 0 TaintedSql errors for safe edge cases, got %d.\nOutput:\n%s",
            $errorCount,
            $output
        ));
    }

    /**
     * Test specific methods are covered in stub
     */
    public function testStubCoversAllMethods(): void
    {
        $stubFile = __DIR__ . '/../../stubs/AuraSql.phpstub';
        $this->assertFileExists($stubFile);

        $stubContent = file_get_contents($stubFile);

        // PdoInterface methods
        $this->assertStringContainsString('function exec(', $stubContent);
        $this->assertStringContainsString('function prepare(', $stubContent);
        $this->assertStringContainsString('function query(', $stubContent);
        $this->assertStringContainsString('function quote(', $stubContent);

        // ExtendedPdoInterface fetch methods
        $this->assertStringContainsString('function fetchAffected(', $stubContent);
        $this->assertStringContainsString('function fetchAll(', $stubContent);
        $this->assertStringContainsString('function fetchAssoc(', $stubContent);
        $this->assertStringContainsString('function fetchCol(', $stubContent);
        $this->assertStringContainsString('function fetchGroup(', $stubContent);
        $this->assertStringContainsString('function fetchObject(', $stubContent);
        $this->assertStringContainsString('function fetchObjects(', $stubContent);
        $this->assertStringContainsString('function fetchOne(', $stubContent);
        $this->assertStringContainsString('function fetchPairs(', $stubContent);
        $this->assertStringContainsString('function fetchValue(', $stubContent);

        // ExtendedPdoInterface execute methods
        $this->assertStringContainsString('function perform(', $stubContent);
        $this->assertStringContainsString('function prepareWithValues(', $stubContent);

        // ExtendedPdoInterface yield methods
        $this->assertStringContainsString('function yieldAll(', $stubContent);
        $this->assertStringContainsString('function yieldAssoc(', $stubContent);
        $this->assertStringContainsString('function yieldCol(', $stubContent);
        $this->assertStringContainsString('function yieldObjects(', $stubContent);
        $this->assertStringContainsString('function yieldPairs(', $stubContent);

        // ExtendedPdoInterface quote methods
        $this->assertStringContainsString('function quoteName(', $stubContent);
        $this->assertStringContainsString('function quoteSingleName(', $stubContent);
    }

    /**
     * Test taint annotations are present
     */
    public function testTaintAnnotationsPresent(): void
    {
        $stubFile = __DIR__ . '/../../stubs/AuraSql.phpstub';
        $stubContent = file_get_contents($stubFile);

        // Count taint-sink annotations (for $statement parameter)
        preg_match_all('/@psalm-taint-sink sql/', $stubContent, $sinkMatches);
        $this->assertGreaterThanOrEqual(17, count($sinkMatches[0]), 'Expected at least 17 taint-sink annotations');

        // Count taint-escape annotations (for $values parameter and quote methods)
        preg_match_all('/@psalm-taint-escape sql/', $stubContent, $escapeMatches);
        $this->assertGreaterThanOrEqual(17, count($escapeMatches[0]), 'Expected at least 17 taint-escape annotations');
    }

    private function runPsalmTaintAnalysis(string $file): string
    {
        $output = [];
        $command = sprintf(
            '%s --threads=1 --taint-analysis --no-cache %s 2>&1',
            escapeshellarg(self::PSALM_BIN),
            escapeshellarg($file)
        );

        exec($command, $output);

        return implode("\n", $output);
    }

    private function countTaintedSqlErrors(string $output): int
    {
        preg_match_all('/TaintedSql/', $output, $matches);

        return count($matches[0]);
    }
}
