<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark;

use BEAR\Security\Scanner;
use BEAR\Security\ScanResult;

/**
 * Benchmark Runner for BEAR.Security Scanner
 *
 * Measures:
 * - Detection Rate (True Positive Rate)
 * - Precision (1 - False Positive Rate)
 * - Performance (files/second, time per file)
 *
 * Usage:
 *   php tests/Benchmark/BenchmarkRunner.php [--level=all|1|2|3|4] [--scale=small|medium|large]
 */
class BenchmarkRunner
{
    private Scanner $scanner;
    private array $results = [];

    public function __construct()
    {
        $this->scanner = new Scanner();
    }

    public function run(array $options = []): void
    {
        $level = $options['level'] ?? 'all';
        $scale = $options['scale'] ?? null;

        echo "==========================================================\n";
        echo "BEAR.Security Benchmark Suite\n";
        echo "==========================================================\n\n";

        // True Positive Tests
        if ($level === 'all' || in_array($level, ['1', '2', '3', '4'])) {
            $this->runTruePositiveTests($level);
        }

        // False Positive Tests
        if ($level === 'all' || $level === 'fp') {
            $this->runFalsePositiveTests();
        }

        // Real-World CVE Tests
        if ($level === 'all' || $level === 'cve') {
            $this->runCveTests();
        }

        // Scale Tests
        if ($scale) {
            $this->runScaleTests($scale);
        }

        // Summary
        $this->printSummary();
    }

    private function runTruePositiveTests(string $level): void
    {
        $levels = [
            '1' => ['Level1_Basic', 'Expected: 100%'],
            '2' => ['Level2_Intermediate', 'Expected: 70-90%'],
            '3' => ['Level3_Advanced', 'Expected: 30-60%'],
            '4' => ['Level4_AIOnly', 'Expected: 0-10% (SAST)'],
        ];

        $toRun = $level === 'all' ? $levels : [$level => $levels[$level] ?? null];

        foreach ($toRun as $key => $config) {
            if (!$config) continue;

            [$dir, $expected] = $config;
            $path = __DIR__ . "/TruePositives/{$dir}";

            if (!is_dir($path)) continue;

            echo "--- True Positives: Level {$key} ({$dir}) ---\n";
            echo "    {$expected}\n\n";

            $result = $this->benchmark($path);
            $this->results["TP_Level{$key}"] = $result;

            $this->printResult($result);
        }
    }

    private function runFalsePositiveTests(): void
    {
        echo "--- False Positive Tests ---\n";
        echo "    Expected: 0 detections (all safe code)\n\n";

        $path = __DIR__ . '/FalsePositives';
        if (!is_dir($path)) {
            echo "    [SKIP] Directory not found\n\n";
            return;
        }

        $result = $this->benchmark($path);
        $result['expected_vulns'] = 0;
        $this->results['FalsePositives'] = $result;

        $this->printResult($result);

        if ($result['total_vulns'] > 0) {
            echo "    ⚠ False Positives Detected:\n";
            foreach ($result['scan_result']->getVulnerabilities() as $vuln) {
                echo "      - {$vuln->getType()}: {$vuln->getFile()}:{$vuln->getLine()}\n";
            }
            echo "\n";
        }
    }

    private function runCveTests(): void
    {
        echo "--- Real-World CVE Pattern Tests ---\n";
        echo "    Expected: High detection rate\n\n";

        $path = __DIR__ . '/RealWorld';
        if (!is_dir($path)) {
            echo "    [SKIP] Directory not found\n\n";
            return;
        }

        $result = $this->benchmark($path);
        $this->results['CVE'] = $result;

        $this->printResult($result);
    }

    private function runScaleTests(string $scale): void
    {
        echo "--- Scale Tests: {$scale} ---\n\n";

        $path = __DIR__ . '/Scale/' . ucfirst($scale);

        // Generate if not exists
        if (!is_dir($path) || count(glob("{$path}/*.php")) === 0) {
            echo "    Generating scale test files...\n";
            $generator = new Scale\Generator();
            $generator->generate($scale);
        }

        $result = $this->benchmark($path);
        $this->results["Scale_{$scale}"] = $result;

        $this->printResult($result);

        // Performance metrics
        $filesPerSecond = $result['files'] / $result['time'];
        $msPerFile = ($result['time'] * 1000) / $result['files'];

        echo "    Performance:\n";
        echo "      Files/second: " . number_format($filesPerSecond, 2) . "\n";
        echo "      ms/file: " . number_format($msPerFile, 2) . "\n\n";
    }

    private function benchmark(string $path): array
    {
        $startTime = microtime(true);
        $startMemory = memory_get_usage(true);

        $scanResult = $this->scanner->scanDirectory($path);

        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        $files = count(glob("{$path}/*.php") ?: []);

        return [
            'path' => $path,
            'files' => $files,
            'time' => $endTime - $startTime,
            'memory' => $endMemory - $startMemory,
            'total_vulns' => count($scanResult->getVulnerabilities()),
            'scan_result' => $scanResult,
            'vulns_by_type' => $this->groupByType($scanResult),
            'vulns_by_severity' => $this->groupBySeverity($scanResult),
        ];
    }

    private function groupByType(ScanResult $result): array
    {
        $groups = [];
        foreach ($result->getVulnerabilities() as $vuln) {
            $type = $vuln->getType();
            $groups[$type] = ($groups[$type] ?? 0) + 1;
        }
        arsort($groups);
        return $groups;
    }

    private function groupBySeverity(ScanResult $result): array
    {
        $groups = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
        foreach ($result->getVulnerabilities() as $vuln) {
            $severity = $vuln->getSeverity();
            $groups[$severity] = ($groups[$severity] ?? 0) + 1;
        }
        return $groups;
    }

    private function printResult(array $result): void
    {
        echo "    Files scanned: {$result['files']}\n";
        echo "    Time: " . number_format($result['time'] * 1000, 2) . " ms\n";
        echo "    Memory: " . number_format($result['memory'] / 1024, 2) . " KB\n";
        echo "    Vulnerabilities found: {$result['total_vulns']}\n";

        if ($result['total_vulns'] > 0) {
            echo "    By severity:\n";
            foreach ($result['vulns_by_severity'] as $severity => $count) {
                if ($count > 0) {
                    echo "      {$severity}: {$count}\n";
                }
            }

            echo "    By type (top 5):\n";
            $i = 0;
            foreach ($result['vulns_by_type'] as $type => $count) {
                echo "      {$type}: {$count}\n";
                if (++$i >= 5) break;
            }
        }

        echo "\n";
    }

    private function printSummary(): void
    {
        echo "==========================================================\n";
        echo "SUMMARY\n";
        echo "==========================================================\n\n";

        $totalFiles = 0;
        $totalTime = 0;
        $totalVulns = 0;

        foreach ($this->results as $name => $result) {
            $totalFiles += $result['files'];
            $totalTime += $result['time'];
            $totalVulns += $result['total_vulns'];
        }

        echo "Total files scanned: {$totalFiles}\n";
        echo "Total time: " . number_format($totalTime * 1000, 2) . " ms\n";
        echo "Total vulnerabilities: {$totalVulns}\n";

        if ($totalFiles > 0 && $totalTime > 0) {
            echo "Average speed: " . number_format($totalFiles / $totalTime, 2) . " files/second\n";
        }

        // Detection rate analysis
        echo "\nDetection Analysis:\n";
        foreach ($this->results as $name => $result) {
            if (str_starts_with($name, 'TP_')) {
                echo "  {$name}: {$result['total_vulns']} vulnerabilities detected\n";
            }
        }

        if (isset($this->results['FalsePositives'])) {
            $fp = $this->results['FalsePositives']['total_vulns'];
            echo "\nFalse Positives: {$fp}\n";
            if ($fp === 0) {
                echo "  ✓ No false positives detected\n";
            } else {
                echo "  ✗ {$fp} false positive(s) need investigation\n";
            }
        }

        echo "\n";
    }
}

// CLI execution
if (PHP_SAPI === 'cli') {
    require_once __DIR__ . '/../../vendor/autoload.php';

    $options = [];
    foreach ($argv as $arg) {
        if (str_starts_with($arg, '--level=')) {
            $options['level'] = substr($arg, 8);
        }
        if (str_starts_with($arg, '--scale=')) {
            $options['scale'] = substr($arg, 8);
        }
    }

    $runner = new BenchmarkRunner();
    $runner->run($options);
}
